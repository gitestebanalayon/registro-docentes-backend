<?php

use Firebase\JWT\JWT;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\Key;
function welcome()
{
    return json_encode(['message' => '¡Bienvenido al PNFD!', 'version' => '2.0.0'], JSON_UNESCAPED_UNICODE);
}

function validarToken($action)
{
    // Excluir 'iniciar_sesion' y tambien verificar_servicio de la validación del token
    if ($action !== 'verificar_servicio' && $action !== 'iniciar_sesion') {
        // Verificar si se ha pasado un token en el encabezado
        if (!isset($_SERVER['HTTP_AUTHORIZATION'])) {
            http_response_code(401);
            echo json_encode([
                'codeStatus' => 401,
                'error' => 'Token no proporcionado',
                'debug' => 'Encabezado Authorization no encontrado'
            ]);
            exit;
        }

        // Obtener el token desde el encabezado Authorization
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
        $token = str_replace('Bearer ', '', $authHeader);

        // Depuración: Imprime el token para verificar que se está recibiendo correctamente
        error_log("Token recibido: " . $token);

        try {
            // Decodificar el token
            $algorithms = [$_ENV['JWT_ALGORITHMS']]; // Asigna el array a una variable
            $secret = $_ENV['JWT_SECRET'];
            $decoded = JWT::decode($token, new Key($secret, $algorithms[0])); // Usar la clase Key
        } catch (ExpiredException $e) {
            http_response_code(401);
            echo json_encode([
                'codeStatus' => 401,
                'error' => 'Token expirado',
                'message' => 'El token ha expirado, por favor obtenga uno nuevo'
            ]);
            exit;
        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode([
                'codeStatus' => 401,
                'error' => 'Unauthorized',
                'message' => $e->getMessage()
            ]);
            exit;
        }
    }
}