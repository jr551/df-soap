<?php
namespace DreamFactory\Core\Soap;

use Str;

/**
 * FunctionSchema is the class for representing the metadata of a WSDL-based SOAP function.
 *
 * FunctionSchema provides the following information about a table:
 * <ul>
 * <li>{@link name}</li>
 * <li>{@link description}</li>
 * <li>{@link requestType}</li>
 * <li>{@link requestFields}</li>
 * <li>{@link responseType}</li>
 * <li>{@link responseFields}</li>
 * </ul>
 *
 */
class FunctionSchema
{
    /**
     * @var string WSDL declared name of this function.
     */
    public $name;
    /**
     * @var string Full description of this function.
     */
    public $description;
    /**
     * @var string Request object type.
     */
    public $requestType;
    /**
     * @var array Request object fields.
     */
    public $requestFields;
    /**
     * @var array Associative array of parameters parsed from the function signature: [name => type]
     */
    public $params = [];
    /**
     * @var string Response object type.
     */
    public $responseType;
    /**
     * @var array Response object fields.
     */
    public $responseFields;

    public function __construct($function)
    {
        // Example signature from SoapClient: "ResponseType FunctionName(ParamType1 param1, ParamType2 param2)"
        $this->name = strstr(substr($function, strpos($function, ' ') + 1), '(', true);
        $this->responseType = strstr($function, ' ', true);
        $inside = trim(strstr($function, '('), '()');
        // Set requestType to the first token for backward compatibility (document/literal wrapper case)
        $this->requestType = strstr($inside, ' ', true);
        // Parse all parameters into $this->params
        $this->params = [];
        if ($inside !== '' && strtolower($inside) !== 'void') {
            foreach (explode(',', $inside) as $raw) {
                $seg = trim($raw);
                if ($seg === '') continue;
                // Expect "Type name"; reduce multiple spaces
                $seg = preg_replace('/\s+/', ' ', $seg);
                $parts = explode(' ', $seg);
                if (count($parts) >= 2) {
                    $name = $parts[count($parts)-1];
                    $type = implode(' ', array_slice($parts, 0, -1));
                    $name = ltrim($name, '$');
                    $this->params[$name] = $type;
                }
            }
        }
    }

    public function fill(array $settings)
    {
        foreach ($settings as $key => $value) {
            if (!property_exists($this, $key)) {
                // try camel cased
                $camel = Str::camel($key);
                if (property_exists($this, $camel)) {
                    $this->{$camel} = $value;
                    continue;
                }
            }
            // set real and virtual
            $this->{$key} = $value;
        }
    }

    public function toArray()
    {
        return (array)$this;
    }
}
