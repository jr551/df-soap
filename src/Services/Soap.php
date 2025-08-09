<?php

namespace DreamFactory\Core\Soap\Services;

use DreamFactory\Core\Components\Cacheable;
use DreamFactory\Core\Enums\ApiOptions;
use DreamFactory\Core\Enums\VerbsMask;
use DreamFactory\Core\Exceptions\InternalServerErrorException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\Services\BaseRestService;
use DreamFactory\Core\Soap\Components\WsseAuthHeader;
use DreamFactory\Core\Soap\FunctionSchema;
use DreamFactory\Core\Utility\ResourcesWrapper;
use Illuminate\Support\Facades\Request;
use Log;
use Symfony\Component\HttpFoundation\Response;
use DreamFactory\Core\Soap\Components\SoapClient;
use Arr;
use Str;

/**
 * Class Soap
 *
 * @package DreamFactory\Core\Soap\Services
 */
class Soap extends BaseRestService
{
    use Cacheable;

    //*************************************************************************
    //* Members
    //*************************************************************************

    /**
     * @var string
     */
    protected $wsdl;
    /**
     * @var SoapClient
     */
    protected $client;
    /**
     * @var \DOMDocument
     */
    protected $dom;
    /**
     * @type bool
     */
    protected $cacheEnabled = false;
    /**
     * @type array
     */
    protected $functions = [];
    /**
     * @type array
     */
    protected $types = [];

    //*************************************************************************
    //* Methods
    //*************************************************************************

    /**
     * Create a new SoapService
     *
     * @param array $settings settings array
     *
     * @throws \DreamFactory\Core\Exceptions\InternalServerErrorException
     */
    public function __construct($settings)
    {
        parent::__construct($settings);
        $config = Arr::get($settings, 'config', []);
        $this->wsdl = Arr::get($config, 'wsdl');

        // Validate url setup
        if (empty($this->wsdl)) {
            // check for location and uri in options
            if (!isset($config['options']['location']) || !isset($config['options']['uri'])) {
                throw new \InvalidArgumentException('SOAP Services require either a WSDL or both location and URI to be configured.');
            }
        } else {
            if ((!str_contains($this->wsdl, '/')) && (!str_contains($this->wsdl, '\\'))) {
                // no directories involved, store it where we want to store it
                if (!empty($storage = storage_path('wsdl'))) {
                    $this->wsdl = rtrim($storage, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $this->wsdl;
                }
            } elseif (false !== $path = realpath($this->wsdl)) {
                $this->wsdl = $path;
            }
        }
        $options = Arr::get($config, 'options', []);
        if (!is_array($options)) {
            $options = [];
        } else {
            foreach ($options as $key => $value) {
                if (!is_numeric($value)) {
                    if (is_string($value) && defined($value)) {
                        $options[$key] = constant($value);
                    }
                    if (0 === strcasecmp($key, 'stream_context')) {
                        // Need to make a stream context out of an array of options
                        if (is_string($value)) {
                            // try to convert json to array
                            $value = json_decode(stripslashes($value), true);
                        }
                        if (!is_array($value)) {
                            throw new \InvalidArgumentException('SOAP Services stream_context must be a valid array (or JSON object) of parameters.');
                        }
                        $context = stream_context_create($value);
                        $options[$key] = $context;
                    }
                }
            }
        }

        $this->cacheEnabled = array_get_bool($config, 'cache_enabled');
        // Safe default TTL when Config facade is not bootstrapped
        $defaultCacheTtl = 300;
        try {
            if (class_exists('\\Illuminate\\Support\\Facades\\Config')) {
                $defaultCacheTtl = (int)\Illuminate\Support\Facades\Config::get('df.default_cache_ttl', $defaultCacheTtl);
            } elseif (class_exists('Config')) {
                $defaultCacheTtl = (int)\Config::get('df.default_cache_ttl', $defaultCacheTtl);
            }
        } catch (\Throwable $ignore) {}
        $this->cacheTTL = intval(Arr::get($config, 'cache_ttl', $defaultCacheTtl));

        try {
            $this->client = new SoapClient($this->wsdl, $options);
            // Load WSDL DOM for robust, namespace-agnostic introspection (optional, non-breaking)
            $this->dom = null;
            if (!empty($this->wsdl)) {
                $dom = new \DOMDocument();
                $prev = libxml_use_internal_errors(true);
                $loaded = @$dom->load($this->wsdl);
                libxml_clear_errors();
                libxml_use_internal_errors($prev);
                if ($loaded) {
                    $dom->preserveWhiteSpace = false;
                    $this->dom = $dom;
                }
            }
            // Avoid Laravel Request facade when not bootstrapped (simulator-safe)
            $queries = [];
            try {
                if (class_exists('\\Illuminate\\Support\\Facades\\Request')) {
                    $queries = \Illuminate\Support\Facades\Request::query();
                } elseif (class_exists('Request')) { // alias may exist in app context
                    $queries = \Request::query();
                }
            } catch (\Throwable $ignore) {}
            if (empty($queries) && isset($_GET) && is_array($_GET)) {
                $queries = $_GET;
            }
            $headers = Arr::get($config, 'headers');
            $wsseUsernameToken = Arr::get($config, 'wsse_username_token');
            $soapHeaders = null;

            if (!empty($headers)) {
                foreach ($headers as $header) {
                    $headerType = Arr::get($header, 'type', 'generic');
                    switch ($headerType) {
                        case 'wsse':
                            $data = (is_null($header) || !is_array($header)) ? [] : $header;

                            if (Arr::get($data, 'name') == 'username'){
                                $username = Arr::get($data, 'data');
                            } elseif (Arr::get($data, 'name') == 'password'){
                                $password = Arr::get($data, 'data');
                            }

                            if (!empty($username) && !empty($password)) {
                                    $soapHeaders[] = new WsseAuthHeader($username, $password, $wsseUsernameToken);
                            }

                            break;
                        default:
                            $data = Arr::get($header, 'data', '{}');
                            if (Str::contains($data, 'df:')) {
                                $param = Str::after($data, 'df:');
                                $data = $queries[$param] ?? '';
                            } else {
                                $data = json_decode(stripslashes($data), true);
                                $data = (is_null($data) || !is_array($data)) ? [] : $data;
                            }
                            $namespace = Arr::get($header, 'namespace');
                            $name = Arr::get($header, 'name');
                            $mustUnderstand = Arr::get($header, 'mustunderstand', false);
                            $actor = Arr::get($header, 'actor');

                            if (!empty($namespace) && !empty($name) && !empty($data)) {
                                $soapHeaders[] = new \SoapHeader($namespace, $name, $data, $mustUnderstand, $actor);
                            }
                    }
                }
                if (!empty($soapHeaders)) {
                    $this->client->__setSoapHeaders($soapHeaders);
                }
            }
        } catch (\Exception $ex) {
            throw new InternalServerErrorException("Unexpected SOAP Service Exception:\n{$ex->getMessage()}");
        }
    }

    public function getResources()
    {
        $refresh = $this->request->getParameterAsBool(ApiOptions::REFRESH);
        $result = $this->getFunctions($refresh);
        $resources = [];
        foreach ($result as $function) {
            $access = $this->getPermissions($function->name);
            if (!empty($access)) {
                $out = $function->toArray();
                $out['access'] = VerbsMask::maskToArray($access);
                $resources[] = $out;
            }
        }

        return $resources;
    }

    /**
     * @param bool $refresh
     *
     * @return FunctionSchema[]
     */
    public function getFunctions($refresh = false)
    {
        if ($refresh ||
            (empty($this->functions) &&
                (null === $this->functions = $this->getFromCache('functions')))
        ) {
            $functions = $this->client->__getFunctions();
            $structures = $this->getTypes($refresh);
            // Build a DOM-derived operation map (namespace-agnostic) for wrapper/type fallbacks
            $opMap = [];
            try {
                foreach ($this->getWsdlOperationsDom() as $op) {
                    if (!empty($op['name'])) {
                        $opMap[strtolower($op['name'])] = $op;
                    }
                }
            } catch (\Throwable $ignore) {
                // Non-fatal: DOM inspection is a best-effort enhancement
            }
            // Build a case-insensitive index of available schema names for reliable lookups
            $schemaIndex = [];
            foreach (array_keys($structures) as $k) {
                $schemaIndex[strtolower($k)] = $k;
            }
            $names = [];
            foreach ($functions as $function) {
                $schema = new FunctionSchema($function);
                $reqKey = $schemaIndex[strtolower($schema->requestType)] ?? null;
                $resKey = $schemaIndex[strtolower($schema->responseType)] ?? null;
                $reqSchema = $reqKey ? ($structures[$reqKey] ?? null) : ($structures[$schema->requestType] ?? null);
                $resSchema = $resKey ? ($structures[$resKey] ?? null) : ($structures[$schema->responseType] ?? null);
                // Normalize to object properties for simulator/example builders
                $schema->requestFields = $this->extractProperties($reqSchema, $structures);
                $schema->responseFields = $this->extractProperties($resSchema, $structures);
                if ($reqKey) { $schema->requestType = $reqKey; }
                if ($resKey) { $schema->responseType = $resKey; }

                // Enhancement: if SoapClient-derived fields are missing or wrapper-only,
                // use DOM operation info to resolve the effective input/output types.
                $key = strtolower($schema->name);
                if (isset($opMap[$key])) {
                    $op = $opMap[$key];
                    // Prefer resolved complex type over element wrapper; fall back to element name
                    $wantReq = $op['input']['type'] ?? null;
                    if (!$wantReq) { $wantReq = $op['input']['element'] ?? null; }
                    if ($wantReq) {
                        $wantReqKey = $schemaIndex[strtolower($wantReq)] ?? null;
                        if ($wantReqKey && isset($structures[$wantReqKey])) {
                            $schema->requestType = $wantReqKey;
                            $schema->requestFields = $this->extractProperties($structures[$wantReqKey], $structures);
                        }
                    }
                    $wantResp = $op['output']['type'] ?? null;
                    if (!$wantResp) { $wantResp = $op['output']['element'] ?? null; }
                    if ($wantResp) {
                        $wantRespKey = $schemaIndex[strtolower($wantResp)] ?? null;
                        if ($wantRespKey && isset($structures[$wantRespKey])) {
                            $schema->responseType = $wantRespKey;
                            $schema->responseFields = $this->extractProperties($structures[$wantRespKey], $structures);
                        }
                    }
                }
                $names[strtolower($schema->name)] = $schema;
            }
            ksort($names);
            $this->functions = $names;
            $this->addToCache('functions', $this->functions, true);
        }

        return $this->functions;
    }

    /**
     * @param bool $refresh
     *
     * @return FunctionSchema[]
     */
    public function getTypes($refresh = false)
    {
        if ($refresh ||
            (empty($this->types) &&
                (null === $this->types = $this->getFromCache('types')))
        ) {
            $types = $this->client->__getTypes();
            // first pass, build name-value pairs for easier lookups
            $structures = [];
            foreach ($types as $type) {
                if (0 === substr_compare($type, 'struct ', 0, 7)) {
                    // declared as "struct type { data_type field; ...}
                    $type = substr($type, 7);
                    $name = strstr($type, ' ', true);
                    $type = trim(strstr($type, ' '), "{} \t\n\r\0\x0B");
                    if (false !== stripos($type, ' complexObjectArray;')) {
                        // declared as "type complexObjectArray"
                        $type = strstr(trim($type), ' complexObjectArray;', true);
                        $structures[$name] = [$type];
                    } else {
                        $parameters = [];
                        foreach (explode(';', $type) as $param) {
                            // declared as "type data_type"
                            $parts = explode(' ', trim($param));
                            if (count($parts) > 1) {
                                $parameters[trim($parts[1])] = trim($parts[0]);
                            }
                        }
                        $structures[$name] = $parameters;
                    }
                } else {
                    // declared as "type data_type"
                    $parts = explode(' ', $type);
                    if (count($parts) > 1) {
                        $structures[$parts[1]] = $parts[0];
                    }
                }
            }
            // Build DOM-derived type map up-front so we can reference complex types instead of downgrading to primitives
            $domTypes = $this->buildTypesFromDom();
            // Build a case-insensitive index of all known type names (DOM wins over SoapClient when both exist)
            $knownIndex = [];
            foreach (array_keys($domTypes) as $k) { $knownIndex[strtolower($k)] = $k; }
            foreach (array_keys($structures) as $k) { $kl = strtolower($k); if (!isset($knownIndex[$kl])) { $knownIndex[$kl] = $k; } }

            foreach ($structures as $name => &$type) {
                if (is_array($type)) {
                    if ((1 === count($type)) && isset($type[0])) {
                        $type = $type[0];
                        // array of type
                        $refKey = $knownIndex[strtolower($type)] ?? null;
                        if ($refKey) {
                            $type = ['type' => 'array', 'items' => ['$ref' => '#/components/schemas/' . $refKey]];
                        } else {
                            // convert simple types to swagger types
                            $newType = static::soapType2ApiDocType($type);
                            $type = ['type' => 'array', 'items' => $newType];
                        }
                    } else {
                        // array of field definitions
                        foreach ($type as $fieldName => &$fieldType) {
                            $refKey = $knownIndex[strtolower($fieldType)] ?? null;
                            if ($refKey) {
                                $fieldType = ['$ref' => '#/components/schemas/' . $refKey];
                            } else {
                                // convert simple types to swagger types
                                $newType = static::soapType2ApiDocType($fieldType);
                                $fieldType = $newType;
                            }
                        }
                        $type = ['type' => 'object', 'properties' => $type];
                    }
                } else {
                    $refKey = $knownIndex[strtolower($type)] ?? null;
                    if ($refKey) {
                        $type = ['$ref' => '#/components/schemas/' . $refKey];
                    } else {
                        // convert simple types to swagger types
                        $newType = static::soapType2ApiDocType($type);
                        $type = $newType;
                    }
                }
            }

            // Merge in richer, DOM-derived schemas (namespace-agnostic), if available (DOM overrides SoapClient types)
            if (!empty($domTypes)) {
                // DOM types override/augment the SoapClient-derived ones by name
                $structures = array_merge($structures, $domTypes);
            }

            ksort($structures);
            $this->types = $structures;
            $this->addToCache('types', $this->types, true);
        }

        return $this->types;
    }

    /**
     * Normalize a schema or reference to its properties map for UI/example usage.
     * Accepts either an OpenAPI object schema, a $ref array, or a plain properties map.
     */
    protected function extractProperties($schemaOrProps, array $allTypes)
    {
        if (empty($schemaOrProps)) { return null; }
        // If already a properties map (heuristic: values are arrays or strings without 'type' key at top)
        if (is_array($schemaOrProps) && !isset($schemaOrProps['type']) && !isset($schemaOrProps['$ref'])) {
            return $schemaOrProps;
        }
        // Handle $ref
        if (is_array($schemaOrProps) && isset($schemaOrProps['$ref'])) {
            $ref = (string)$schemaOrProps['$ref'];
            $name = ($ref && strrpos($ref, '/') !== false) ? substr($ref, strrpos($ref, '/')+1) : $ref;
            $target = $allTypes[$name] ?? null;
            if (is_array($target)) {
                // Some entries are already a properties map, others are full object schemas
                if (isset($target['properties']) && is_array($target['properties'])) {
                    return $target['properties'];
                }
                return $target; // likely already a properties map
            }
        }
        // Full object schema
        if (is_array($schemaOrProps) && isset($schemaOrProps['type']) && $schemaOrProps['type'] === 'object') {
            return $schemaOrProps['properties'] ?? [];
        }
        return null;
    }

    /**
     *
     */

    /**
     *
     */
    public function refreshTableCache()
    {
        $this->removeFromCache('functions');
        $this->functions = [];
        $this->removeFromCache('types');
        $this->types = [];
    }

    /**
     * @param string $name       The name of the function to check
     * @param bool   $returnName If true, the function name is returned instead of TRUE
     *
     * @throws \InvalidArgumentException
     * @return bool|string
     */
    public function doesFunctionExist($name, $returnName = false)
    {
        if (empty($name)) {
            throw new \InvalidArgumentException('Function name cannot be empty.');
        }

        //  Build the lower-cased table array
        $functions = $this->getFunctions(false);

        //	Search normal, return real name
        $ndx = strtolower($name);
        if (isset($functions[$ndx])) {
            return $returnName ? $functions[$ndx]->name : true;
        }

        return false;
    }

    protected function getEventName()
    {
        if (!empty($this->resourcePath)) {
            return parent::getEventName() . '.' . str_replace('/', '.', trim($this->resourcePath, '/'));
        }

        return parent::getEventName();
    }

    /**
     * Runs pre process tasks/scripts
     */
    protected function preProcess()
    {
        $this->checkPermission($this->getRequestedAction(), $this->name);

        parent::preProcess();
    }

    protected function formatPayload(&$payload)
    {
        if (!is_array($payload)) {
            return;
        }
        foreach ($payload as $key => &$value) {
            if (is_array($value)) {
                if (0 === strcasecmp('soapvar', $key)) {
                    $data = Arr::get($value, 'data');
                    if ($encoding = Arr::get($value, 'encoding')) {
                        // see if there is a constant usage
                        if (!is_numeric($encoding)) {
                            if (defined($encoding)) {
                                $encoding = constant($encoding);
                            }
                        }
                    } else {
                        // attempt to determine it
                        switch (gettype($data)) {
                            case 'array':
                                $encoding = SOAP_ENC_ARRAY;
                                break;
                            case 'object':
                                $encoding = SOAP_ENC_OBJECT;
                                break;
                            case 'boolean':
                                $encoding = XSD_BOOLEAN;
                                break;
                            case 'double':
                                $encoding = XSD_DOUBLE;
                                break;
                            case 'integer':
                                $encoding = XSD_INTEGER;
                                break;
                            case 'string':
                                $encoding = XSD_STRING;
                                break;
                        }
                    }

                    $payload = new \SoapVar(
                        $data,
                        $encoding,
                        Arr::get($value, 'type_name'),
                        Arr::get($value, 'type_namespace'),
                        Arr::get($value, 'node_name'),
                        Arr::get($value, 'node_namespace')
                    );
                } else {
                    $this->formatPayload($value);
                }
            }
        }
    }

    /**
     * @param $function
     * @param $payload
     *
     * @return mixed
     * @throws \DreamFactory\Core\Exceptions\NotFoundException
     * @throws InternalServerErrorException
     */
    protected function callFunction($function, $payload)
    {
        if (false === ($function = $this->doesFunctionExist($function, true))) {
            throw new NotFoundException("Function '$function' does not exist on this service.");
        }

        if (is_array($payload)) {
            $this->formatPayload($payload);
        }
        try {
            $result = $this->client->$function($payload);
            $result = static::object2Array($result);

            // debugging help
            if ($last = $this->client->__getLastRequest()) {
                Log::debug($this->name . ' last SOAP request: ' . $last);
            }
            if ($lastHeaders = $this->client->__getLastRequestHeaders()) {
                Log::debug($this->name . ' last SOAP request headers: ' . $lastHeaders);
            }
            if ($last = $this->client->__getLastResponse()) {
                Log::debug($this->name . ' last SOAP response: ' . $last);
            }
            if ($lastHeaders = $this->client->__getLastResponseHeaders()) {
                Log::debug($this->name . ' last SOAP response headers: ' . $lastHeaders);
            }

            return $result;
        } catch (\SoapFault $e) {
            // debugging help
            if ($last = $this->client->__getLastRequest()) {
                Log::debug($this->name . ' failed SOAP request: ' . $last);
            }
            if ($lastHeaders = $this->client->__getLastRequestHeaders()) {
                Log::debug($this->name . ' failed SOAP request headers: ' . $lastHeaders);
            }

            /** @noinspection PhpUndefinedFieldInspection */
            $faultCode = (property_exists($e, 'faultcode') ? $e->faultcode : $e->getCode());
            $errorCode = Response::HTTP_INTERNAL_SERVER_ERROR;
            // Fault code can be a string.
            if (is_numeric($faultCode) && !str_contains($faultCode, '.')) {
                $errorCode = $faultCode;
            }
            throw new InternalServerErrorException($e->getMessage() . ' [Fault code:' . $faultCode . ']', $errorCode);
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function handleGet()
    {
        if (empty($this->resource)) {
            return parent::handleGET();
        }

        $result = $this->callFunction($this->resource, $this->request->getParameters());

        $asList = $this->request->getParameterAsBool(ApiOptions::AS_LIST);
        $idField = $this->request->getParameter(ApiOptions::ID_FIELD, static::getResourceIdentifier());
        $result = ResourcesWrapper::cleanResources($result, $asList, $idField, ApiOptions::FIELDS_ALL, !empty($meta));

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    protected function handlePost()
    {
        if (empty($this->resource)) {
            // not currently supported, maybe batch opportunity?
            return false;
        }

        $result = $this->callFunction($this->resource, $this->request->getPayloadData());

        $asList = $this->request->getParameterAsBool(ApiOptions::AS_LIST);
        $idField = $this->request->getParameter(ApiOptions::ID_FIELD, static::getResourceIdentifier());
        $result = ResourcesWrapper::cleanResources($result, $asList, $idField, ApiOptions::FIELDS_ALL, !empty($meta));

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    protected function getApiDocPaths()
    {
        $capitalized = camelize($this->name);

        $paths = [
            '/' => [
                'get' => [
                    'summary'     => 'Get resources for this service.',
                    'operationId' => 'get' . $capitalized . 'Resources',
                    'description' => 'Return an array of the resources available.',
                    'parameters'  => [
                        ApiOptions::documentOption(ApiOptions::AS_LIST),
                        ApiOptions::documentOption(ApiOptions::AS_ACCESS_LIST),
                        ApiOptions::documentOption(ApiOptions::INCLUDE_ACCESS),
                        ApiOptions::documentOption(ApiOptions::REFRESH),
                    ],
                    'responses'   => [
                        '200' => ['$ref' => '#/components/responses/SoapResponse']
                    ],
                ],
            ],
        ];
        foreach ($this->getFunctions() as $resource) {
            $paths['/' . $resource->name] = [
                'post' => [
                    'summary'     => 'call the ' . $resource->name . ' operation.',
                    'description' => is_null($resource->description) ? '' : $resource->description,
                    'operationId' => 'call' . $capitalized . $resource->name,
                    'requestBody' => [
                        '$ref' => '#/components/requestBodies/' . $resource->requestType
                    ],
                    'responses'   => [
                        '200' => ['$ref' => '#/components/responses/' . $resource->responseType]
                    ],
                ],
            ];
        }

        return $paths;
    }

    protected function getApiDocRequests()
    {
        $requests = [];
        foreach ($this->getFunctions() as $resource) {
            $requests[$resource->requestType] = [
                'description' => $resource->requestType . ' Request',
                'content'     => [
                    'application/json' => [
                        'schema' => ['$ref' => '#/components/schemas/' . $resource->requestType]
                    ],
                    'application/xml'  => [
                        'schema' => ['$ref' => '#/components/schemas/' . $resource->requestType]
                    ],
                ],
            ];
        }

        return $requests;
    }

    protected function getApiDocResponses()
    {
        $responses = [
            'SoapResponse' => [
                'description' => 'SOAP Response',
                'content'     => [
                    'application/json' => [
                        'schema' => ['$ref' => '#/components/schemas/SoapResponse']
                    ],
                    'application/xml'  => [
                        'schema' => ['$ref' => '#/components/schemas/SoapResponse']
                    ],
                ],
            ],
        ];

        foreach ($this->getFunctions() as $resource) {
            $responses[$resource->responseType] = [
                'description' => $resource->responseType . ' Response',
                'content'     => [
                    'application/json' => [
                        'schema' => ['$ref' => '#/components/schemas/' . $resource->responseType]
                    ],
                    'application/xml'  => [
                        'schema' => ['$ref' => '#/components/schemas/' . $resource->responseType]
                    ],
                ],
            ];
        }

        return $responses;
    }

    protected function getApiDocSchemas()
    {
        $wrapper = ResourcesWrapper::getWrapper();

        $models = [
            'SoapResponse' => [
                'type'       => 'object',
                'properties' => [
                    $wrapper => [
                        'type'        => 'array',
                        'description' => 'Array of system records.',
                        'items'       => [
                            '$ref' => '#/components/schemas/SoapMethods',
                        ],
                    ],
                ],
            ],
            'SoapMethods'  => [
                'type'       => 'object',
                'properties' => [
                    'name'           => [
                        'type'        => 'string',
                        'description' => 'A URL to the target host.',
                    ],
                    'description'    => [
                        'type'        => 'string',
                        'description' => 'An optional string describing the host designated by the URL.',
                    ],
                    'requestType'    => [
                        'type'        => 'string',
                        'description' => 'An optional string describing the host designated by the URL.',
                    ],
                    'requestFields'  => [
                        'type'        => 'object',
                        'description' => 'An optional string describing the host designated by the URL.',
                    ],
                    'responseType'   => [
                        'type'        => 'string',
                        'description' => 'An optional string describing the host designated by the URL.',
                    ],
                    'responseFields' => [
                        'type'        => 'object',
                        'description' => 'An optional string describing the host designated by the URL.',
                    ],
                    'access'         => [
                        'type'        => 'array',
                        'items'       => ['type' => 'string'],
                        'description' => 'An array of verbs allowed.',
                    ],
                ],
            ],
        ];

        return array_merge($models, $this->getTypes());
    }

    protected static function soapType2ApiDocType($name)
    {
        switch ($name) {
            case 'byte':
                return ['type' => 'number', 'format' => 'int8', 'description' => 'signed 8-bit integer'];
            case 'unsignedByte':
                return ['type' => 'number', 'format' => 'int8', 'description' => 'unsigned 8-bit integer'];
            case 'short':
                return ['type' => 'number', 'format' => 'int16', 'description' => 'signed 16-bit integer'];
            case 'unsignedShort':
                return ['type' => 'number', 'format' => 'int8', 'description' => 'unsigned 16-bit integer'];
            case 'int':
            case 'integer':
            case 'negativeInteger':    // An integer containing only negative values (..,-2,-1)
            case 'nonNegativeInteger': // An integer containing only non-negative values (0,1,2,..)
            case 'nonPositiveInteger':    // An integer containing only non-positive values (..,-2,-1,0)
            case 'positiveInteger': // An integer containing only positive values (1,2,..)
                return ['type' => 'number', 'format' => 'int32', 'description' => 'signed 32-bit integer'];
            case 'unsignedInt':
                return ['type' => 'number', 'format' => 'int32', 'description' => 'unsigned 32-bit integer'];
            case 'long':
                return ['type' => 'number', 'format' => 'int64', 'description' => 'signed 64-bit integer'];
            case 'unsignedLong':
                return ['type' => 'number', 'format' => 'int8', 'description' => 'unsigned 64-bit integer'];
            case 'float':
                return ['type' => 'number', 'format' => 'float', 'description' => 'float'];
            case 'double':
                return ['type' => 'number', 'format' => 'double', 'description' => 'double'];
            case 'decimal':
                return ['type' => 'number', 'description' => 'decimal'];
            case 'string':
                return ['type' => 'string', 'description' => 'string'];
            case 'base64Binary':
                return ['type' => 'string', 'format' => 'byte', 'description' => 'Base64-encoded characters'];
            case 'hexBinary':
                return ['type' => 'string', 'format' => 'binary', 'description' => 'hexadecimal-encoded characters'];
            case 'binary':
                return ['type' => 'string', 'format' => 'binary', 'description' => 'any sequence of octets'];
            case 'boolean':
                return ['type' => 'boolean', 'description' => 'true or false'];
            case 'date':
                return ['type' => 'string', 'format' => 'date', 'description' => 'As defined by full-date - RFC3339'];
            case 'time':
                return ['type' => 'string', 'description' => 'As defined by time - RFC3339'];
            case 'dateTime':
                return [
                    'type'        => 'string',
                    'format'      => 'date-time',
                    'description' => 'As defined by date-time - RFC3339'
                ];
            case 'gYearMonth':
            case 'gYear':
            case 'gMonthDay':
            case 'gDay':
            case 'gMonth':
                return [
                    'type'        => 'string',
                    'format'      => 'date-time',
                    'description' => 'As defined by date-time - RFC3339'
                ];
            case 'duration':
                return [
                    'type'        => 'string',
                    'description' => 'Duration or time interval as specified in the following form "PnYnMnDTnHnMnS".'
                ];
            case 'password':
                return [
                    'type'        => 'string',
                    'format'      => 'password',
                    'description' => 'Used to hint UIs the input needs to be obscured'
                ];
            case 'anySimpleType': // SOAP specific, use swagger's Any Type {} or no type
                return ['description' => 'any simple type'];
            case 'anyType': // SOAP specific, use swagger's Any Type {} or no type
                return ['description' => 'any type'];
            case 'anyURI':
                return ['type' => 'string', 'format' => 'uri', 'description' => 'any valid URI'];
            case 'anyXML': // SOAP specific, use swagger's Any Type {} or no type
            case '<anyXML>': // SOAP specific, use swagger's Any Type {} or no type
                return ['description' => 'any XML'];
            // derived string types
            case 'QName':
            case 'NOTATION':
            case 'normalizedString':
            case 'token':
            case 'language':
            case 'ID':
            case 'IDREF':
            case 'IDREFS':
            case 'ENTITY':
            case 'ENTITIES':
            case 'NMTOKEN':
            case 'NMTOKENS':
            case 'Name':
            case 'NCName':
                return ['type' => 'string', 'description' => 'derived string type: ' . $name];
            default: // undetermined type, return string for now
                \Log::alert('SOAP to Swagger type unknown: ' . print_r($name, true));
                if (!is_string($name)) {
                    $name = 'object or array';
                }

                return ['type' => 'string', 'description' => 'undetermined type: ' . $name];
        }
    }

    /**
     * @param $object
     *
     * @return array
     */
    protected static function object2Array($object)
    {
        if (is_object($object)) {
            return array_map([static::class, __FUNCTION__], get_object_vars($object));
        } elseif (is_array($object)) {
            return array_map([static::class, __FUNCTION__], $object);
        } else {
            return $object;
        }
    }

    /**
     * Build a minimal object schema for a named struct using SoapClient types only.
     * Used as a fallback when DOM doesn't contain imported base types.
     */
    protected function clientTypeSchema(string $typeName): ?array
    {
        if (!$this->client) {
            return null;
        }
        try {
            $types = $this->client->__getTypes();
        } catch (\Throwable $e) {
            return null;
        }
        foreach ($types as $type) {
            if (0 !== substr_compare($type, 'struct ', 0, 7)) {
                continue;
            }
            // declared as "struct TypeName { data_type field; ... }"
            $def = substr($type, 7);
            $brace = strpos($def, '{');
            if ($brace === false) {
                continue;
            }
            $name = trim(substr($def, 0, $brace));
            if (0 !== strcasecmp($name, $typeName)) {
                continue;
            }
            $body = trim(substr($def, $brace + 1));
            // remove ending '}' if present
            if (str_ends_with($body, '}')) {
                $body = substr($body, 0, -1);
            }
            $properties = [];
            $parts = explode(';', $body);
            foreach ($parts as $part) {
                $part = trim($part);
                if ($part === '') {
                    continue;
                }
                // Expect "Type field" or "Type[] field"
                $segments = preg_split('/\s+/', $part);
                if (count($segments) < 2) {
                    continue;
                }
                $t = $segments[0];
                $field = $segments[1];
                $isArray = false;
                if (substr($t, -2) === '[]') {
                    $isArray = true;
                    $t = substr($t, 0, -2);
                }
                $schema = static::soapType2ApiDocType($t);
                if ($isArray) {
                    $schema = ['type' => 'array', 'items' => $schema];
                }
                $properties[$field] = $schema;
            }
            return ['type' => 'object', 'properties' => $properties];
        }
        return null;
    }

    protected static function domCheckTypeForEnum($dom, $type)
    {
        $values = [];
        $node = static::domFindType($dom, $type);
        if (!$node || !$dom instanceof \DOMDocument) {
            return $values;
        }
        $xp = new \DOMXPath($dom);
        $value_list = $xp->query('.//*[local-name()="enumeration"]', $node);
        if (!$value_list || $value_list->length == 0) {
            return $values;
        }
        for ($i = 0; $i < $value_list->length; $i++) {
            $attr = $value_list->item($i)->attributes->getNamedItem('value');
            if ($attr) { $values[] = $attr->nodeValue; }
        }

        return $values;
    }

    /**
     * Look for a type
     *
     * @param \DOMDocument $dom
     * @param string       $class
     *
     * @return \DOMNode
     */
    protected static function domFindType($dom, $class)
    {
        // Backward-compatible: prefer robust XPath search across prefixes, checking both simpleType and complexType
        if (!$dom instanceof \DOMDocument) { return null; }
        $xp = new \DOMXPath($dom);
        // DOMXPath in PHP doesn't support variable bindings in query directly; emulate with string replace (safe here)
        // Search anywhere under each schema for named simpleType/complexType to catch nested declarations
        $needle = str_replace('"','""', $class);
        $q = '/*[local-name()="definitions"]/*[local-name()="types"]/*[local-name()="schema"]'
           . '//*[local-name()="simpleType" or local-name()="complexType"][ @name = "' . $needle . '" ]';
        $nodes = $xp->query($q);
        return ($nodes && $nodes->length) ? $nodes->item(0) : null;
    }

    /**
     * New, namespace-agnostic WSDL inspection helpers (non-breaking additions)
     */
    protected static function createXPath(\DOMDocument $dom): \DOMXPath
    {
        return new \DOMXPath($dom);
    }

    protected static function qnameLocal(?string $qname): ?string
    {
        if ($qname === null) return null;
        $pos = strrpos($qname, ':');
        return $pos === false ? $qname : substr($qname, $pos + 1);
    }

    /**
     * Build OpenAPI component schemas from the WSDL DOM.
     * Produces schemas for named simpleType/complexType and top-level elements (wrappers).
     */
    protected function buildTypesFromDom(): array
    {
        $result = [];
        if (!$this->dom instanceof \DOMDocument) {
            return $result;
        }

        $xp = static::createXPath($this->dom);
        $schemaPath = '/*[local-name()="definitions"]/*[local-name()="types"]/*[local-name()="schema"]';

        // Discover known named types first (for $ref decisions)
        $known = [];
        // Include any named type anywhere under the schema (not only direct children)
        $ctNodes = $xp->query($schemaPath . '//*[local-name()="complexType"][@name]');
        foreach ($ctNodes as $ct) { /** @var \DOMElement $ct */ $known[$ct->getAttribute('name')] = true; }
        $stNodes = $xp->query($schemaPath . '//*[local-name()="simpleType"][@name]');
        foreach ($stNodes as $st) { /** @var \DOMElement $st */ $known[$st->getAttribute('name')] = true; }

        // Build schemas for named complexType
        foreach ($ctNodes as $ct) {
            /** @var \DOMElement $ct */
            $name = $ct->getAttribute('name');
            if (!$name) { continue; }
            $schema = $this->domBuildComplexType($xp, $ct, $known);
            if (!empty($schema)) {
                $result[$name] = $schema;
            }
        }

        // Build schemas for named simpleType (with enumerations if any)
        foreach ($stNodes as $st) {
            /** @var \DOMElement $st */
            $name = $st->getAttribute('name');
            if (!$name) { continue; }
            $base = null;
            $restriction = $xp->query('./*[local-name()="restriction"]', $st)->item(0);
            if ($restriction instanceof \DOMElement) {
                $base = static::qnameLocal($restriction->getAttribute('base'));
            }
            $schema = $base ? static::soapType2ApiDocType($base) : ['type' => 'string'];
            $enums = static::domCheckTypeForEnum($this->dom, $name);
            if (!empty($enums)) {
                $schema['enum'] = array_values($enums);
            }
            $result[$name] = $schema;
        }

        // Build schemas for top-level elements (often operation wrappers)
        $elNodes = $xp->query($schemaPath . '/*[local-name()="element"][@name]');
        foreach ($elNodes as $el) {
            /** @var \DOMElement $el */
            $name = $el->getAttribute('name');
            if (!$name) { continue; }
            $typeAttr = $el->getAttribute('type');
            if (!empty($typeAttr)) {
                $tLocal = static::qnameLocal($typeAttr);
                if (isset($known[$tLocal])) {
                    $result[$name] = ['$ref' => '#/components/schemas/' . $tLocal];
                } else {
                    $result[$name] = static::soapType2ApiDocType($tLocal);
                }
                continue;
            }
            // Inline complexType
            $ct = $xp->query('./*[local-name()="complexType"]', $el)->item(0);
            if ($ct instanceof \DOMElement) {
                $schema = $this->domBuildComplexType($xp, $ct, $known);
                if (!empty($schema)) {
                    $result[$name] = $schema;
                }
            }
        }

        return $result;
    }

    /**
     * Build an object schema from a complexType element
     */
    protected function domBuildComplexType(\DOMXPath $xp, \DOMElement $ct, array $known): array
    {
        $props = [];
        $required = [];

        // Handle complexContent extension: merge base type properties/required and then add extension's own sequence
        $ext = $xp->query('./*[local-name()="complexContent"]/*[local-name()="extension"]', $ct)->item(0);
        if ($ext instanceof \DOMElement) {
            $baseAttr = $ext->getAttribute('base');
            if (!empty($baseAttr)) {
                $baseLocal = static::qnameLocal($baseAttr);
                // Find base type in DOM and build its schema to flatten properties
                $baseNode = static::domFindType($this->dom, $baseLocal);
                if ($baseNode instanceof \DOMElement) {
                    $baseSchema = $this->domBuildComplexType($xp, $baseNode, $known);
                    if (is_array($baseSchema)) {
                        if (!empty($baseSchema['properties']) && is_array($baseSchema['properties'])) {
                            $props = array_merge($props, $baseSchema['properties']);
                        }
                        if (!empty($baseSchema['required']) && is_array($baseSchema['required'])) {
                            $required = array_merge($required, $baseSchema['required']);
                        }
                    }
                } else {
                    // Fallback: if the base type is defined in an imported XSD not present in the DOM,
                    // attempt to derive its schema from SoapClient's __getTypes() output so we don't lose inherited fields.
                    $baseSchema = $this->clientTypeSchema($baseLocal);
                    if (is_array($baseSchema)) {
                        if (!empty($baseSchema['properties']) && is_array($baseSchema['properties'])) {
                            $props = array_merge($props, $baseSchema['properties']);
                        }
                        if (!empty($baseSchema['required']) && is_array($baseSchema['required'])) {
                            $required = array_merge($required, $baseSchema['required']);
                        }
                    }
                }
            }

            // Elements inside the extension's sequence
            $extEls = $xp->query('./*[local-name()="sequence"]/*[local-name()="element"]', $ext);
            if ($extEls && $extEls->length) {
                foreach ($extEls as $child) {
                    /** @var \DOMElement $child */
                    $pname = $child->getAttribute('name') ?: 'item';
                    $maxOccurs = $child->getAttribute('maxOccurs');
                    $minOccurs = $child->getAttribute('minOccurs');
                    $isArray = ($maxOccurs === 'unbounded') || (ctype_digit($maxOccurs) && intval($maxOccurs) > 1);
                    if ($minOccurs === '' || $minOccurs === null) { $minOccurs = '1'; }
                    if ($minOccurs !== '0') { $required[] = $pname; }

                    $schema = null;
                    $tAttr = $child->getAttribute('type');
                    if (!empty($tAttr)) {
                        $tLocal = static::qnameLocal($tAttr);
                        if (isset($known[$tLocal])) {
                            $schema = ['$ref' => '#/components/schemas/' . $tLocal];
                        } else {
                            $schema = static::soapType2ApiDocType($tLocal);
                        }
                    } else {
                        // Handle referenced element (@ref)
                        $refAttr = $child->getAttribute('ref');
                        if (!empty($refAttr)) {
                            $refLocal = static::qnameLocal($refAttr);
                            $refNode = $xp->query('/*[local-name()="definitions"]/*[local-name()="types"]/*[local-name()="schema"]/*[local-name()="element"][@name="' . $refLocal . '"]')->item(0);
                            if ($refNode instanceof \DOMElement) {
                                $refType = $refNode->getAttribute('type');
                                if (!empty($refType)) {
                                    $tLocal = static::qnameLocal($refType);
                                    if (isset($known[$tLocal])) {
                                        $schema = ['$ref' => '#/components/schemas/' . $tLocal];
                                    } else {
                                        $schema = static::soapType2ApiDocType($tLocal);
                                    }
                                } else {
                                    $inlineCt = $xp->query('./*[local-name()="complexType"]', $refNode)->item(0);
                                    if ($inlineCt instanceof \DOMElement) {
                                        $schema = $this->domBuildComplexType($xp, $inlineCt, $known);
                                    } else {
                                        $inlineSt = $xp->query('./*[local-name()="simpleType"]', $refNode)->item(0);
                                        if ($inlineSt instanceof \DOMElement) {
                                            $base = null;
                                            $restriction = $xp->query('./*[local-name()="restriction"]', $inlineSt)->item(0);
                                            if ($restriction instanceof \DOMElement) {
                                                $base = static::qnameLocal($restriction->getAttribute('base'));
                                            }
                                            $schema = $base ? static::soapType2ApiDocType($base) : ['type' => 'string'];
                                        }
                                    }
                                }
                            }
                        } else {
                            // Inline simpleType or complexType
                            $st = $xp->query('./*[local-name()="simpleType"]', $child)->item(0);
                            if ($st instanceof \DOMElement) {
                                $base = null;
                                $restriction = $xp->query('./*[local-name()="restriction"]', $st)->item(0);
                                if ($restriction instanceof \DOMElement) { $base = static::qnameLocal($restriction->getAttribute('base')); }
                                $schema = $base ? static::soapType2ApiDocType($base) : ['type' => 'string'];
                                $enums = [];
                                $enumNodes = $xp->query('.//*[local-name()="enumeration"]', $st);
                                if ($enumNodes && $enumNodes->length) {
                                    foreach ($enumNodes as $en) { /** @var \DOMElement $en */ $v = $en->getAttribute('value'); if ($v !== '') { $enums[] = $v; } }
                                }
                                if (!empty($enums)) { $schema['enum'] = $enums; }
                            } else {
                                $inlineCt = $xp->query('./*[local-name()="complexType"]', $child)->item(0);
                                $schema = $inlineCt instanceof \DOMElement ? $this->domBuildComplexType($xp, $inlineCt, $known) : ['type' => 'object'];
                            }
                        }
                    }

                    if ($isArray) { $schema = ['type' => 'array', 'items' => $schema]; }
                    $props[$pname] = $schema;
                }
            }
        }

        // sequence elements
        $seqEls = $xp->query('./*[local-name()="sequence"]/*[local-name()="element"]', $ct);
        if ($seqEls && $seqEls->length) {
            foreach ($seqEls as $child) {
                /** @var \DOMElement $child */
                $pname = $child->getAttribute('name') ?: 'item';
                $maxOccurs = $child->getAttribute('maxOccurs');
                $minOccurs = $child->getAttribute('minOccurs');
                $isArray = ($maxOccurs === 'unbounded') || (ctype_digit($maxOccurs) && intval($maxOccurs) > 1);
                if ($minOccurs === '' || $minOccurs === null) { $minOccurs = '1'; }
                if ($minOccurs !== '0') { $required[] = $pname; }

                $schema = null;
                $tAttr = $child->getAttribute('type');
                if (!empty($tAttr)) {
                    $tLocal = static::qnameLocal($tAttr);
                    if (isset($known[$tLocal])) {
                        $schema = ['$ref' => '#/components/schemas/' . $tLocal];
                    } else {
                        $schema = static::soapType2ApiDocType($tLocal);
                    }
                } else {
                    // No explicit type: check @ref or inline definitions
                    $refAttr = $child->getAttribute('ref');
                    if (!empty($refAttr)) {
                        $refLocal = static::qnameLocal($refAttr);
                        $refNode = $xp->query('/*[local-name()="definitions"]/*[local-name()="types"]/*[local-name()="schema"]/*[local-name()="element"][@name="' . $refLocal . '"]')->item(0);
                        if ($refNode instanceof \DOMElement) {
                            $refType = $refNode->getAttribute('type');
                            if (!empty($refType)) {
                                $tLocal = static::qnameLocal($refType);
                                if (isset($known[$tLocal])) {
                                    $schema = ['$ref' => '#/components/schemas/' . $tLocal];
                                } else {
                                    $schema = static::soapType2ApiDocType($tLocal);
                                }
                            } else {
                                $inlineCt = $xp->query('./*[local-name()="complexType"]', $refNode)->item(0);
                                if ($inlineCt instanceof \DOMElement) {
                                    $schema = $this->domBuildComplexType($xp, $inlineCt, $known);
                                } else {
                                    $inlineSt = $xp->query('./*[local-name()="simpleType"]', $refNode)->item(0);
                                    if ($inlineSt instanceof \DOMElement) {
                                        $base = null;
                                        $restriction = $xp->query('./*[local-name()="restriction"]', $inlineSt)->item(0);
                                        if ($restriction instanceof \DOMElement) {
                                            $base = static::qnameLocal($restriction->getAttribute('base'));
                                        }
                                        $schema = $base ? static::soapType2ApiDocType($base) : ['type' => 'string'];
                                    }
                                }
                            }
                        }
                    } else {
                        // Inline simpleType or complexType
                        $st = $xp->query('./*[local-name()="simpleType"]', $child)->item(0);
                        if ($st instanceof \DOMElement) {
                            $base = null;
                            $restriction = $xp->query('./*[local-name()="restriction"]', $st)->item(0);
                            if ($restriction instanceof \DOMElement) {
                                $base = static::qnameLocal($restriction->getAttribute('base'));
                            }
                            $schema = $base ? static::soapType2ApiDocType($base) : ['type' => 'string'];
                            $enums = [];
                            $enumNodes = $xp->query('.//*[local-name()="enumeration"]', $st);
                            if ($enumNodes && $enumNodes->length) {
                                foreach ($enumNodes as $en) { /** @var \DOMElement $en */ $v = $en->getAttribute('value'); if ($v !== '') { $enums[] = $v; } }
                            }
                            if (!empty($enums)) { $schema['enum'] = $enums; }
                        } else {
                            // Inline complexType
                            $inlineCt = $xp->query('./*[local-name()="complexType"]', $child)->item(0);
                            if ($inlineCt instanceof \DOMElement) {
                                $schema = $this->domBuildComplexType($xp, $inlineCt, $known);
                            } else {
                                $schema = ['type' => 'object'];
                            }
                        }
                    }
                }

                if ($isArray) {
                    $schema = ['type' => 'array', 'items' => $schema];
                }
                $props[$pname] = $schema;
            }
        }

        // 'all' group elements (unordered, 0..1 each)
        $allEls = $xp->query('./*[local-name()="all"]/*[local-name()="element"]', $ct);
        if ($allEls && $allEls->length) {
            foreach ($allEls as $child) {
                /** @var \DOMElement $child */
                $pname = $child->getAttribute('name') ?: 'item';
                $minOccurs = $child->getAttribute('minOccurs');
                if ($minOccurs === '' || $minOccurs === null) { $minOccurs = '1'; }
                if ($minOccurs !== '0') { $required[] = $pname; }

                $schema = null;
                $tAttr = $child->getAttribute('type');
                if (!empty($tAttr)) {
                    $tLocal = static::qnameLocal($tAttr);
                    $schema = isset($known[$tLocal]) ? ['$ref' => '#/components/schemas/' . $tLocal] : static::soapType2ApiDocType($tLocal);
                } else {
                    $refAttr = $child->getAttribute('ref');
                    if (!empty($refAttr)) {
                        $refLocal = static::qnameLocal($refAttr);
                        $refNode = $xp->query('/*[local-name()="definitions"]/*[local-name()="types"]/*[local-name()="schema"]/*[local-name()="element"][@name="' . $refLocal . '"]')->item(0);
                        if ($refNode instanceof \DOMElement) {
                            $refType = $refNode->getAttribute('type');
                            if (!empty($refType)) {
                                $tLocal = static::qnameLocal($refType);
                                $schema = isset($known[$tLocal]) ? ['$ref' => '#/components/schemas/' . $tLocal] : static::soapType2ApiDocType($tLocal);
                            } else {
                                $inlineCt = $xp->query('./*[local-name()="complexType"]', $refNode)->item(0);
                                if ($inlineCt instanceof \DOMElement) {
                                    $schema = $this->domBuildComplexType($xp, $inlineCt, $known);
                                } else {
                                    $inlineSt = $xp->query('./*[local-name()="simpleType"]', $refNode)->item(0);
                                    if ($inlineSt instanceof \DOMElement) {
                                        $base = null;
                                        $restriction = $xp->query('./*[local-name()="restriction"]', $inlineSt)->item(0);
                                        if ($restriction instanceof \DOMElement) {
                                            $base = static::qnameLocal($restriction->getAttribute('base'));
                                        }
                                        $schema = $base ? static::soapType2ApiDocType($base) : ['type' => 'string'];
                                    }
                                }
                            }
                        }
                    } else {
                        // Inline definitions on the element
                        $st = $xp->query('./*[local-name()="simpleType"]', $child)->item(0);
                        if ($st instanceof \DOMElement) {
                            $base = null;
                            $restriction = $xp->query('./*[local-name()="restriction"]', $st)->item(0);
                            if ($restriction instanceof \DOMElement) { $base = static::qnameLocal($restriction->getAttribute('base')); }
                            $schema = $base ? static::soapType2ApiDocType($base) : ['type' => 'string'];
                        } else {
                            $inlineCt = $xp->query('./*[local-name()="complexType"]', $child)->item(0);
                            $schema = $inlineCt instanceof \DOMElement ? $this->domBuildComplexType($xp, $inlineCt, $known) : ['type' => 'object'];
                        }
                    }
                }
                $props[$pname] = $schema ?: ['type' => 'string'];
            }
        }

        // 'choice' group -> map to OpenAPI oneOf
        $oneOf = [];
        $choiceNodes = $xp->query('./*[local-name()="choice"]', $ct);
        if ($choiceNodes && $choiceNodes->length) {
            foreach ($choiceNodes as $choice) {
                /** @var \DOMElement $choice */
                $els = $xp->query('./*[local-name()="element"]', $choice);
                foreach ($els as $child) {
                    /** @var \DOMElement $child */
                    $pname = $child->getAttribute('name') ?: 'item';
                    $maxOccurs = $child->getAttribute('maxOccurs');
                    $isArray = ($maxOccurs === 'unbounded') || (ctype_digit($maxOccurs) && intval($maxOccurs) > 1);

                    $schema = null;
                    $tAttr = $child->getAttribute('type');
                    if (!empty($tAttr)) {
                        $tLocal = static::qnameLocal($tAttr);
                        $schema = isset($known[$tLocal]) ? ['$ref' => '#/components/schemas/' . $tLocal] : static::soapType2ApiDocType($tLocal);
                    } else {
                        $refAttr = $child->getAttribute('ref');
                        if (!empty($refAttr)) {
                            $refLocal = static::qnameLocal($refAttr);
                            $refNode = $xp->query('/*[local-name()="definitions"]/*[local-name()="types"]/*[local-name()="schema"]/*[local-name()="element"][@name="' . $refLocal . '"]')->item(0);
                            if ($refNode instanceof \DOMElement) {
                                $refType = $refNode->getAttribute('type');
                                if (!empty($refType)) {
                                    $tLocal = static::qnameLocal($refType);
                                    $schema = isset($known[$tLocal]) ? ['$ref' => '#/components/schemas/' . $tLocal] : static::soapType2ApiDocType($tLocal);
                                } else {
                                    $inlineCt = $xp->query('./*[local-name()="complexType"]', $refNode)->item(0);
                                    if ($inlineCt instanceof \DOMElement) {
                                        $schema = $this->domBuildComplexType($xp, $inlineCt, $known);
                                    } else {
                                        $inlineSt = $xp->query('./*[local-name()="simpleType"]', $refNode)->item(0);
                                        if ($inlineSt instanceof \DOMElement) {
                                            $base = null;
                                            $restriction = $xp->query('./*[local-name()="restriction"]', $inlineSt)->item(0);
                                            if ($restriction instanceof \DOMElement) { $base = static::qnameLocal($restriction->getAttribute('base')); }
                                            $schema = $base ? static::soapType2ApiDocType($base) : ['type' => 'string'];
                                        }
                                    }
                                }
                            }
                        } else {
                            $st = $xp->query('./*[local-name()="simpleType"]', $child)->item(0);
                            if ($st instanceof \DOMElement) {
                                $base = null;
                                $restriction = $xp->query('./*[local-name()="restriction"]', $st)->item(0);
                                if ($restriction instanceof \DOMElement) { $base = static::qnameLocal($restriction->getAttribute('base')); }
                                $schema = $base ? static::soapType2ApiDocType($base) : ['type' => 'string'];
                            } else {
                                $inlineCt = $xp->query('./*[local-name()="complexType"]', $child)->item(0);
                                $schema = $inlineCt instanceof \DOMElement ? $this->domBuildComplexType($xp, $inlineCt, $known) : ['type' => 'object'];
                            }
                        }
                    }

                    if ($isArray) { $schema = ['type' => 'array', 'items' => $schema]; }
                    $oneOf[] = ['type' => 'object', 'properties' => [$pname => $schema]];
                }
            }
        }

        $out = ['type' => 'object', 'properties' => $props];
        if (!empty($required)) { $out['required'] = array_values(array_unique($required)); }
        if (!empty($oneOf)) { $out['oneOf'] = $oneOf; }
        return $out;
    }

    protected function getWsdlMessagesMap(): array
    {
        if (!$this->dom) return [];
        $xp = static::createXPath($this->dom);
        $msgs = [];
        $messageNodes = $xp->query('/*[local-name()="definitions"]/*[local-name()="message"]');
        foreach ($messageNodes as $m) {
            /** @var \DOMElement $m */
            $name = $m->getAttribute('name');
            $parts = [];
            foreach ($m->getElementsByTagName('*') as $child) {
                if (strtolower($child->localName) !== 'part') continue;
                /** @var \DOMElement $child */
                $parts[] = [
                    'name'    => $child->getAttribute('name') ?: null,
                    'element' => $child->getAttribute('element') ?: null,
                    'type'    => $child->getAttribute('type') ?: null,
                ];
            }
            if ($name) $msgs[$name] = ['name' => $name, 'parts' => $parts];
        }
        return $msgs;
    }

    /**
     * Attempt to resolve wrapper element to an effective type (doc/literal wrapped pattern)
     */
    protected function resolveWrapperType(string $elementLocalName): ?string
    {
        if (!$this->dom) return null;
        $xp = static::createXPath($this->dom);
        // Find global element by @name
        $q = '/*[local-name()="definitions"]/*[local-name()="types"]/*[local-name()="schema"]'
           . '/*[local-name()="element"][ @name = "' . str_replace('"','""',$elementLocalName) . '" ]';
        $nodes = $xp->query($q);
        if (!$nodes || !$nodes->length) return null;
        /** @var \DOMElement $el */
        $el = $nodes->item(0);
        // If element has explicit type, return its local name
        $t = $el->getAttribute('type');
        if ($t) return static::qnameLocal($t);
        // Else look for single child under complexType/sequence/element with @type
        $childs = $xp->query('./*[local-name()="complexType"]/*[local-name()="sequence"]/*[local-name()="element"]', $el);
        if ($childs && $childs->length === 1) {
            /** @var \DOMElement $c */
            $c = $childs->item(0);
            $ct = $c->getAttribute('type');
            if ($ct) return static::qnameLocal($ct);
        }
        return null;
    }

    /**
     * Public: discover operations/messages via DOM (namespace-agnostic). Does not alter existing behavior.
     * Returns: [ [ name, input: { message, element?, type? }, output: {...}, rawParts: {...} ] ]
     */
    public function getWsdlOperationsDom(): array
    {
        if (!$this->dom) return [];
        $xp = static::createXPath($this->dom);
        $msgMap = $this->getWsdlMessagesMap();

        $ops = [];
        $opNodes = $xp->query('/*[local-name()="definitions"]/*[local-name()="portType"]/*[local-name()="operation"]');
        foreach ($opNodes as $op) {
            /** @var \DOMElement $op */
            $name = $op->getAttribute('name') ?: null;
            $inEl = null; $inType = null; $outEl = null; $outType = null; $inMsg = null; $outMsg = null; $inParts = null; $outParts = null;
            $in = $xp->query('./*[local-name()="input"]', $op)->item(0);
            $out = $xp->query('./*[local-name()="output"]', $op)->item(0);
            if ($in instanceof \DOMElement) {
                $inMsg = $in->getAttribute('message') ?: null;
                $inParts = ($inMsg && isset($msgMap[$inMsg])) ? $msgMap[$inMsg]['parts'] : null;
                if (is_array($inParts) && count($inParts) === 1 && !empty($inParts[0]['element'])) {
                    $inEl = static::qnameLocal($inParts[0]['element']);
                    $inType = $inEl ? $this->resolveWrapperType($inEl) : null;
                }
            }
            if ($out instanceof \DOMElement) {
                $outMsg = $out->getAttribute('message') ?: null;
                $outParts = ($outMsg && isset($msgMap[$outMsg])) ? $msgMap[$outMsg]['parts'] : null;
                if (is_array($outParts) && count($outParts) === 1 && !empty($outParts[0]['element'])) {
                    $outEl = static::qnameLocal($outParts[0]['element']);
                    $outType = $outEl ? $this->resolveWrapperType($outEl) : null;
                }
            }
            $ops[] = [
                'name'   => $name,
                'input'  => ['message' => $inMsg, 'element' => $inEl, 'type' => $inType, 'rawParts' => $inParts],
                'output' => ['message' => $outMsg, 'element' => $outEl, 'type' => $outType, 'rawParts' => $outParts],
            ];
        }
        return $ops;
    }
}
