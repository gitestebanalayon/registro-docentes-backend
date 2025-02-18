<?php
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    // Respuesta para solicitudes de preflight
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE');
    header('Access-Control-Allow-Headers: Authorization, X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Request-Method');
    header('Access-Control-Max-Age: 86400'); // Cache preflight por 1 día
    exit(0);
}

// Configurar encabezados CORS para todas las respuestas
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE');
header('Access-Control-Allow-Headers: Authorization, X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Request-Method');

// Incluir dependencias / estas importaciones depende de la ubicación de los archivos de producción
require 'vendor/autoload.php';
require 'conexion/database.php';
require 'funciones/metodos.php';

// Incluir validación de tokens
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Obtener las conexiones de PostgreSQL y MariaDB
$pdoPostgres = connectPostgres();
$pdoMariaDB = connectMariaDB();


// Obtener el método de la solicitud
$method = $_SERVER['REQUEST_METHOD'];

switch ($method) {
    case 'POST':
        $input = json_decode(file_get_contents("php://input"), true);

        if (isset($_GET['action'])) {
            $action = $_GET['action'];

            validarToken($action);

            switch ($action) {
                case 'registrar':
                    // Registro de Usuario
                    if (!isset($input['nombre'], $input['apellido'], $input['cedula'], $input['correo'], $input['password'])) {
                        http_response_code(400);
                        echo json_encode(['error' => 'Faltan datos para registro']);
                        exit;
                    }

                    $nombre = htmlspecialchars($input['nombre']);
                    $apellido = htmlspecialchars($input['apellido']);
                    $cedula = htmlspecialchars($input['cedula']);
                    $correo = htmlspecialchars($input['correo']);
                    $password = password_hash($input['password'], PASSWORD_BCRYPT); // Encriptar la contraseña

                    try {
                        // Verificar si el correo ya está registrado
                        $stmt = $pdoPostgres->prepare("SELECT id FROM pnfd_cuenta.usuarios WHERE correo = :correo");
                        $stmt->bindParam(':correo', $correo, PDO::PARAM_STR);
                        $stmt->execute();
                        if ($stmt->fetch(PDO::FETCH_ASSOC)) {
                            http_response_code(400);
                            throw new Exception('El correo ya está registrado');
                        }

                        // Verificar si la cédula ya está registrada
                        $stmt = $pdoPostgres->prepare("SELECT id FROM pnfd_cuenta.usuarios WHERE cedula = :cedula");
                        $stmt->bindParam(':cedula', $cedula, PDO::PARAM_STR);
                        $stmt->execute();
                        if ($stmt->fetch(PDO::FETCH_ASSOC)) {
                            http_response_code(400);
                            throw new Exception('El usuario con cédula ' . $cedula . ' ya existe');
                        }

                        // Preparar la consulta para insertar el usuario
                        $stmt = $pdoPostgres->prepare("INSERT INTO pnfd_cuenta.usuarios (nombre, apellido, cedula, correo, password) 
                                                  VALUES (:nombre, :apellido, :cedula, :correo, :password)");
                        $stmt->bindParam(':nombre', $nombre, PDO::PARAM_STR);
                        $stmt->bindParam(':apellido', $apellido, PDO::PARAM_STR);
                        $stmt->bindParam(':cedula', $cedula, PDO::PARAM_STR);
                        $stmt->bindParam(':correo', $correo, PDO::PARAM_STR);
                        $stmt->bindParam(':password', $password, PDO::PARAM_STR);

                        $stmt->execute();

                        http_response_code(201);
                        echo json_encode([
                            'statusCode' => 201,
                            'message' => 'Usuario registrado con éxito'
                        ]);
                    } catch (Exception $e) {
                        http_response_code(400);
                        echo json_encode([
                            'statusCode' => 400,
                            'message' => $e->getMessage(),
                        ]);
                    } catch (PDOException $e) {
                        http_response_code(500);
                        echo json_encode([
                            'statusCode' => 500,
                            'message' => $e->getMessage(),
                        ]);
                    }
                    break;

                case 'iniciar_sesion':
                    // Login de Usuario
                    if (!isset($input['correo'], $input['password'])) {
                        http_response_code(400);
                        echo json_encode(['error' => 'Faltan datos para login']);
                        exit;
                    }

                    $correo = htmlspecialchars($input['correo']);
                    $password = $input['password'];

                    try {
                        // Buscar usuario en la base de datos
                        $stmt = $pdoPostgres->prepare("SELECT id, nombre, apellido, cedula, correo, password FROM pnfd_cuenta.usuarios WHERE correo = :correo");
                        $stmt->bindParam(':correo', $correo, PDO::PARAM_STR);
                        $stmt->execute();
                        $usuario = $stmt->fetch(PDO::FETCH_ASSOC);

                        if (!$usuario || !password_verify($password, $usuario['password'])) {
                            http_response_code(400);
                            throw new Exception('Credenciales incorrectas');
                        }

                        // Generar token JWT
                        $payload = [
                            "iat" => time(),
                            "exp" => time() + (60 * 60),
                            "sub" => $usuario['id'],
                            "nombre" => $usuario['nombre'],
                            "apellido" => $usuario['apellido'],
                            "correo" => $usuario['correo']
                        ];

                        $jwt = JWT::encode($payload, $_ENV['JWT_SECRET'], $_ENV['JWT_ALGORITHMS']);

                        http_response_code(200);
                        echo json_encode([
                            'statusCode' => 200,
                            'token' => $jwt
                        ]);
                    } catch (Exception $e) {
                        http_response_code(400);
                        echo json_encode([
                            'statusCode' => 400,
                            'message' => $e->getMessage(),
                        ]);
                    } catch (PDOException $e) {
                        http_response_code(500);
                        echo json_encode([
                            'statusCode' => 500,
                            'message' => $e->getMessage(),
                        ]);
                    }
                    break;

                case 'validar_token':
                    // Validación del token
                    if (!isset($input['token'])) {
                        http_response_code(400);
                        echo json_encode(['statusCode' => 400, 'error' => 'Falta el campo requerido: token']);
                        exit;
                    }

                    $token = $input['token'];

                    try {
                        // Decodificar el token
                        $secret = $_ENV['JWT_SECRET'];
                        $algorithm = $_ENV['JWT_ALGORITHMS']; // Algoritmo a usar

                        // Decodificar el token
                        $decoded = JWT::decode($token, new Key($secret, $algorithm));

                        // Validación del tiempo restante en el token
                        $exp_time = $decoded->exp;
                        $current_time = time();
                        $time_left = $exp_time - $current_time;

                        if ($time_left > 0) {
                            $minutes_left = floor($time_left / 60);
                            $seconds_left = $time_left % 60;

                            http_response_code(200);
                            echo json_encode([
                                'statusCode' => 200,
                                'message' => '¡Token válidado exitosamente!',
                                'time_left' => [
                                    'minutes' => $minutes_left,
                                    'seconds' => $seconds_left
                                ]
                            ]);
                        } else {
                            http_response_code(401);
                            echo json_encode([
                                'statusCode' => 401,
                                'error' => 'Token expirado',
                                'message' => 'El token ha expirado, por favor obtenga uno nuevo'
                            ]);
                        }
                    } catch (ExpiredException $e) {
                        http_response_code(401);
                        echo json_encode([
                            'statusCode' => 401,
                            'error' => 'Token expirado',
                            'message' => 'El token ha expirado, por favor obtenga uno nuevo'
                        ]);
                    } catch (Exception $e) {
                        http_response_code(401);
                        echo json_encode([
                            'statusCode' => 401,
                            'error' => 'El token no es válido',
                            'message' => $e->getMessage()
                        ]);
                    }
                    break;
                case 'registrar_docente':
                    // Campos requeridos para crear un docente
                    $requiredFields = ['cedula', 'nacionalidad', 'nombres', 'apellidos', 'genero', 'estado_id', 'municipio_id', 'parroquia_me_id', 'correo', 'telefono', 'direccion', 'nivel_instruccion_id', 'nivel_id', 'subnivel_id', 'chamilo_user', 'chamilo_pass', 'cdependencia', 'ddependencia', 'completado'];
                    foreach ($requiredFields as $field) {
                        if (!isset($input[$field])) {
                            http_response_code(400);
                            echo json_encode(['statusCode' => 400, 'error' => 'Falta el campo requerido: ' . $field]);
                            exit;
                        }
                    }

                    try {
                        $query = "INSERT INTO pnfd.docentes (nacionalidad, cedula, nombres, apellidos, genero, estado_id, municipio_id, parroquia_id, direccion, correo, telefono, nivel_instruccion_id, nivel_id, subnivel_id, chamilo_user, chamilo_pass, cdependencia, ddependencia, completado) 
                                  VALUES (:nacionalidad, :cedula, :nombres, :apellidos, :genero, :estado_id, :municipio_id, :parroquia_me_id, :direccion, :correo, :telefono, :nivel_instruccion_id, :nivel_id, :subnivel_id, :chamilo_user, :chamilo_pass, :cdependencia, :ddependencia, :completado)";
                        $stmt = $pdoPostgres->prepare($query);

                        // Vinculación con tipos de datos
                        $stmt->bindParam(':nacionalidad', $input['nacionalidad'], PDO::PARAM_STR);
                        $stmt->bindParam(':cedula', $input['cedula'], PDO::PARAM_INT);
                        $stmt->bindParam(':nombres', $input['nombres'], PDO::PARAM_STR);
                        $stmt->bindParam(':apellidos', $input['apellidos'], PDO::PARAM_STR);
                        $stmt->bindParam(':genero', $input['genero'], PDO::PARAM_STR);
                        $stmt->bindParam(':estado_id', $input['estado_id'], PDO::PARAM_INT);
                        $stmt->bindParam(':municipio_id', $input['municipio_id'], PDO::PARAM_INT);
                        $stmt->bindParam(':parroquia_me_id', $input['parroquia_me_id'], PDO::PARAM_INT);
                        $stmt->bindParam(':direccion', $input['direccion'], PDO::PARAM_STR);
                        $stmt->bindParam(':correo', $input['correo'], PDO::PARAM_STR);
                        $stmt->bindParam(':telefono', $input['telefono'], PDO::PARAM_STR);
                        $stmt->bindParam(':nivel_instruccion_id', $input['nivel_instruccion_id'], PDO::PARAM_INT);
                        $stmt->bindParam(':nivel_id', $input['nivel_id'], PDO::PARAM_INT);
                        $stmt->bindParam(':subnivel_id', $input['subnivel_id'], PDO::PARAM_INT);
                        $stmt->bindParam(':chamilo_user', $input['chamilo_user'], PDO::PARAM_STR);
                        $stmt->bindParam(':chamilo_pass', $input['chamilo_pass'], PDO::PARAM_STR);
                        $stmt->bindParam(':cdependencia', $input['cdependencia'], PDO::PARAM_STR);
                        $stmt->bindParam(':ddependencia', $input['ddependencia'], PDO::PARAM_STR);
                        $stmt->bindParam(':completado', $input['completado'], PDO::PARAM_BOOL);

                        $stmt->execute();

                        echo json_encode(['message' => 'Docente creado exitosamente.']);
                    } catch (PDOException $e) {
                        echo json_encode(['error' => $e->getMessage()]);
                    }

                    break;

                default:
                    http_response_code(400);
                    echo json_encode(['statusCode' => 400, 'error' => 'Acción no válida']);
                    break;
            }
        } else {
            echo welcome();
        }
        break;

    case 'GET':
        $input = json_decode(file_get_contents("php://input"), true);

        if (isset($_GET['action'])) {
            $action = $_GET['action'];

            validarToken($action);

            switch ($action) {
                case 'verificar_servicio':
                    http_response_code(200);
                    echo json_encode([
                        'statusCode' => 200,
                        'message' => '¡Servicio disponible!'
                    ], JSON_UNESCAPED_UNICODE);
                    break;

                case 'verificar_docente':
                    $cedula = $input['cedula'] ?? null;
                    if (!$cedula) {
                        http_response_code(400);
                        echo json_encode(['statusCode' => 400, 'error' => 'Cédula no proporcionada']);
                        exit;
                    }

                    try {
                        $query = "SELECT * FROM dbautogestion.dir_sup WHERE cedula = :cedula";
                        $stmt = $pdoPostgres->prepare($query);
                        $stmt->bindParam(':cedula', $cedula, PDO::PARAM_INT);
                        $stmt->execute();
                        $result = $stmt->fetch(PDO::FETCH_ASSOC);

                        http_response_code($result ? 200 : 404);
                        echo json_encode(['statusCode' => $result ? 200 : 404, 'data' => $result ?: 'No se encontraron datos.'], JSON_UNESCAPED_UNICODE);
                    } catch (Exception $e) {
                        http_response_code(400);
                        echo json_encode([
                            'statusCode' => 400,
                            'message' => $e->getMessage(),
                        ]);
                    } catch (PDOException $e) {
                        http_response_code(500);
                        echo json_encode([
                            'statusCode' => 500,
                            'message' => $e->getMessage(),
                        ]);
                    }
                    break;

                case 'obtener_formacion':
                    try {
                        $stmt = $pdoPostgres->prepare("SELECT * FROM pnfd.formacion WHERE estatus = true");
                        $stmt->execute();
                        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

                        http_response_code($result ? 200 : 404);
                        echo json_encode(['statusCode' => $result ? 200 : 404, 'data' => $result ?: 'No se encontraron datos.'], JSON_UNESCAPED_UNICODE);
                    } catch (Exception $e) {
                        http_response_code(400);
                        echo json_encode([
                            'statusCode' => 400,
                            'message' => $e->getMessage(),
                        ]);
                    } catch (PDOException $e) {
                        http_response_code(500);
                        echo json_encode([
                            'statusCode' => 500,
                            'message' => $e->getMessage(),
                        ]);
                    }
                    break;

                case 'obtener_niveles_instrucciones':
                    try {
                        $query = "SELECT id, nombre FROM pnfd.nivel_instruccion WHERE estatus = true ORDER BY id ASC";
                        $stmt = $pdoPostgres->prepare($query);
                        $stmt->execute();
                        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

                        http_response_code($result ? 200 : 404);
                        echo json_encode(['statusCode' => $result ? 200 : 404, 'data' => $result ?: 'No se encontraron datos.'], JSON_UNESCAPED_UNICODE);
                    } catch (Exception $e) {
                        http_response_code(400);
                        echo json_encode([
                            'statusCode' => 400,
                            'message' => $e->getMessage(),
                        ]);
                    } catch (PDOException $e) {
                        http_response_code(500);
                        echo json_encode([
                            'statusCode' => 500,
                            'message' => $e->getMessage(),
                        ]);
                    }
                    break;

                case 'obtener_nivel':
                    try {
                        $query = "SELECT id, nombre FROM pnfd.tipo_nivel WHERE estatus = true ORDER BY id ASC";
                        $stmt = $pdoPostgres->prepare($query);
                        $stmt->execute();
                        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

                        http_response_code($result ? 200 : 404);
                        echo json_encode(['statusCode' => $result ? 200 : 404, 'data' => $result ?: 'No se encontraron datos.'], JSON_UNESCAPED_UNICODE);
                    } catch (Exception $e) {
                        http_response_code(400);
                        echo json_encode([
                            'statusCode' => 400,
                            'message' => $e->getMessage(),
                        ]);
                    } catch (PDOException $e) {
                        http_response_code(500);
                        echo json_encode([
                            'statusCode' => 500,
                            'message' => $e->getMessage(),
                        ]);
                    }
                    break;

                case 'obtener_subnivel':
                    try {
                        $nivel_id = $input['nivel_id'] ?? null;
                        if (!$nivel_id) {
                            http_response_code(400);
                            echo json_encode(['statusCode' => 400, 'error' => 'nivel_id no proporcionado']);
                            exit;
                        }

                        $query = "SELECT id, nombre FROM pnfd.tipo_subnivel WHERE nivel_id = :nivel_id ORDER BY id ASC";
                        $stmt = $pdoPostgres->prepare($query);
                        $stmt->bindParam(':nivel_id', $nivel_id, PDO::PARAM_INT);
                        $stmt->execute();
                        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

                        http_response_code($result ? 200 : 404);
                        echo json_encode(['statusCode' => $result ? 200 : 404, 'data' => $result ?: 'No se encontraron datos.'], JSON_UNESCAPED_UNICODE);
                    } catch (Exception $e) {
                        http_response_code(400);
                        echo json_encode([
                            'statusCode' => 400,
                            'message' => $e->getMessage(),
                        ]);
                    } catch (PDOException $e) {
                        http_response_code(500);
                        echo json_encode([
                            'statusCode' => 500,
                            'message' => $e->getMessage(),
                        ]);
                    }
                    break;

                case 'obtener_estados':
                    try {
                        $query = "SELECT id, nombre, capital FROM geo.estado";
                        $stmt = $pdoPostgres->prepare($query);
                        $stmt->execute();
                        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

                        http_response_code($result ? 200 : 404);
                        echo json_encode(['statusCode' => $result ? 200 : 404, 'data' => $result ?: 'No se encontraron datos.'], JSON_UNESCAPED_UNICODE);
                    } catch (Exception $e) {
                        http_response_code(400);
                        echo json_encode([
                            'statusCode' => 400,
                            'message' => $e->getMessage(),
                        ]);
                    } catch (PDOException $e) {
                        http_response_code(500);
                        echo json_encode([
                            'statusCode' => 500,
                            'message' => $e->getMessage(),
                        ]);
                    }
                    break;

                case 'obtener_municipios':
                    try {
                        $estado_me_id = $input['estado_me_id'] ?? null;
                        if (!$estado_me_id) {
                            http_response_code(400);
                            echo json_encode(['statusCode' => 400, 'error' => 'estado_me_id no proporcionado']);
                            exit;
                        }

                        $query = "SELECT * FROM geo.municipio WHERE estado_me_id = :estado_me_id";
                        $stmt = $pdoPostgres->prepare($query);
                        $stmt->bindParam(':estado_me_id', $estado_me_id, PDO::PARAM_INT);
                        $stmt->execute();
                        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

                        http_response_code($result ? 200 : 404);
                        echo json_encode(['statusCode' => $result ? 200 : 404, 'data' => $result ?: 'No se encontraron datos.'], JSON_UNESCAPED_UNICODE);
                    } catch (Exception $e) {
                        http_response_code(400);
                        echo json_encode([
                            'statusCode' => 400,
                            'message' => $e->getMessage(),
                        ]);
                    } catch (PDOException $e) {
                        http_response_code(500);
                        echo json_encode([
                            'statusCode' => 500,
                            'message' => $e->getMessage(),
                        ]);
                    }
                    break;

                case 'obtener_parroquias':
                    try {
                        $municipio_me_id = $input['municipio_me_id'] ?? null;
                        if (!$municipio_me_id) {
                            http_response_code(400);
                            echo json_encode(['statusCode' => 400, 'error' => 'municipio_me_id no proporcionado']);
                            exit;
                        }

                        $query = "SELECT * FROM geo.parroquia WHERE municipio_me_id = :municipio_me_id";
                        $stmt = $pdoPostgres->prepare($query);
                        $stmt->bindParam(':municipio_me_id', $municipio_me_id, PDO::PARAM_INT);
                        $stmt->execute();
                        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

                        http_response_code($result ? 200 : 404);
                        echo json_encode(['statusCode' => $result ? 200 : 404, 'data' => $result ?: 'No se encontraron datos.'], JSON_UNESCAPED_UNICODE);
                    } catch (Exception $e) {
                        http_response_code(400);
                        echo json_encode([
                            'statusCode' => 400,
                            'message' => $e->getMessage(),
                        ]);
                    } catch (PDOException $e) {
                        http_response_code(500);
                        echo json_encode([
                            'statusCode' => 500,
                            'message' => $e->getMessage(),
                        ]);
                    }
                    break;

                default:
                    http_response_code(400);
                    echo json_encode(['statusCode' => 400, 'error' => 'Acción no válida']);
                    break;
            }
        } else {
            echo welcome();
        }
        break;


    default:
        http_response_code(405);
        echo json_encode([
            'statusCode' => 405,
            'error' => 'Método no permitido'
        ]);
        break;
}

