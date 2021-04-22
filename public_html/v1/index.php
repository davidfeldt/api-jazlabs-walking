<?php

require '../../vendor/autoload.php';

require_once 'include/DbHandler.php';

use \Firebase\JWT\JWT;
use \Slim\Slim;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;


$dotenv = new Dotenv\Dotenv('../../');
$dotenv->load();
$dotenv->required('DB_USERNAME', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME')->notEmpty();
$dotenv->required('JWT_SECRET', 'JWT_LEEWAY')->notEmpty();

$app = new \Slim\Slim();


function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT' || $_SERVER['REQUEST_METHOD'] == 'POST') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field])) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }

    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response['error'] = true;
        $response['message'] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoResponse(400, $response);
        $app->stop();
    }
}

function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response['error'] = true;
        $response['message'] = 'Email address is not valid';
        echoResponse(400, $response);
        $app->stop();
    }
}


function echoResponse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);

    // setting response content type to json
    $app->contentType('application/json');

    echo json_encode($response);
}

function generateJWT($username) {

	$key 		= $_ENV['JWT_SECRET'];
	$db 		= new DbHandler();
	$result = $db->getProfileByUsername($username);

	$payload= array(
	    "iss" 			     => "https://spectacularapps.us",
	    "aud" 			     => "http://spectacularapps.us",
	    "iat" 			     => time(),
	    "nbf" 			     => time(),
			"username" 		   => $username,
      "fullName"       => $result['fullName'],
      "email"          => $result['email'],
      "mobilephone"    => $result['mobilephone'],
      "profileVisible" => $result['profileVisible'] == 1
	);

	$db = NULL;

	return JWT::encode($payload, $key);

}


function authenticate(\Slim\Route $route) {
    $response = array();
    $app = \Slim\Slim::getInstance();
	// Get the X_AUTHORIZATION header
	$headers = $app->request->headers;
	$token = isset($headers['x-authorization']) ? $headers['x-authorization'] : '';
    // Verifying Authorization Header As Valid JWT Token
    try {
        // give 60 seconds leeway for JWT token
        JWT::$leeway = $_ENV['JWT_LEEWAY'];
        $key = $_ENV['JWT_SECRET'];
        $decoded = JWT::decode($token, $key, array('HS256'));

        if (!empty($decoded)) {
            $app->username      = $decoded->username;

        } else {
            $response['error']   = true;
            $response['message'] = 'Access Denied. Invalid API token';
            echoResponse(401, $response);
            $app->stop();
        }
    } catch (Exception $e) {
        // api key is missing in header
        $response['error']   = true;
        $response['message'] = 'Token error: '.$e->getMessage();
        echoResponse(401, $response);
        $app->stop();
    }
}


function formatPhoneNumber($sPhone){
	if (empty($sPhone)) return "";

	$sPhone = trim($sPhone);
	if(strlen($sPhone) != 10) return "Error";

	$sArea = substr($sPhone,0,3);
	$sPrefix = substr($sPhone,3,3);
	$sNumber = substr($sPhone,6,4);
	$sPhone = "(".$sArea.") ".$sPrefix."-".$sNumber;
	return($sPhone);
}

// dummy response

$app->get('/', function() {

	$response['success'] = true;
	$response['message'] = 'Spectacular Apps Platform v1';

	echoResponse(200, $response);

});

// login

$app->post('/users/auth', function() use($app) {
    // body passed as JSON

    $json = $app->request->getBody();
		$data = json_decode($json, true);
		$username = $data['username'];
		$password = $data['password'];

    $response = array();

    $db = new DbHandler();
    $result = $db->checkLogin($username,$password);

    // $db-> registerAPICall($username, 'login', 'post', $result);

    if ($result == 'valid') {
      $profile = $db->getProfileByUsername($username);
      $app->username = $username;
      $response = array (
        'success'		      => true,
        'username'        => $profile['username'],
        'token'			      => generateJWT($profile['username']),
        "fullName"        => $profile['fullName'],
        "email"           => $profile['email'],
        "mobilephone"     => $profile['mobilephone'],
        "profileVisible"  => $profile['profileVisible'] == 1
      );

    }

    if ($result == 'not_username' || $result == 'not_password') {
    	$response['error'] 		= true;
      $response['message'] 	= 'Incorrect username or password';
    }

		  $db = NULL;
    echoResponse(200, $response);
  });

$app->post('/users/signup', function() use($app) {
    // body passed as JSON

    $json = $app->request->getBody();
		$data = json_decode($json, true);
		$firstName = !empty($data['firstName']) ? ucwords($data['firstName']) : '';
		$lastName = !empty($data['lastName']) ? ucwords($data['lastName']) : '';
		$email = !empty($data['email']) ? strtolower(trim($data['email'])) : '';
		$mobilephone = !empty($data['mobilephone']) ? formatPhoneNumber($data['mobilephone']) : '';
		$password = !empty($data['password']) ? $data['password'] : '';

    $response = array();

    $db = new DbHandler();
    $result = $db->addUser($firstName, $lastName, $email, $mobilephone, $password);

    // $db-> registerAPICall($username, 'login', 'post', $result);

    if (array_key_exists('success', $result) && $result['success']) {
      $response = array (
        'success'		      => true,
        'username'        => $result['username'],
        'token'			      => generateJWT($result['username']),
        "fullName"        => $result['fullName'],
        "email"           => $result['email'],
        "mobilephone"     => $result['mobilephone'],
        "profileVisible"  => $result['profileVisible'] == 1
      );

    } else {
      $response['error'] 		= true;
      $response['message'] 	= 'Something went wrong. Try again later!';
    }

		$db = NULL;
    echoResponse(200, $response);
  });

$app->post('/users/password/forgot', function() use($app) {
            // check for required params
            $json = $app->request->getBody();
    		$data = json_decode($json, true);
    		$username = $data['username'];

            $response = array();

            $db = new DbHandler();
            $res = $db->forgotPassword($username);
 			$db->registerAPICall($username, 'forgot', 'post', $res);

            if ($res == 'not_username') {
                $response['error'] = true;
                $response['message'] = 'No such username: '.$username;
            } else {
                $response['error'] = false;
                $response['success'] = true;
                $response['type'] = $res;
                if ($res == 'mobile') {
                    $message = 'Please enter short code we just sent via SMS';
                }

                if ($res == 'email') {
                    $message = 'Please click on the reset password link in the email we just sent you to reset your password';
                }
                $response['message'] = $message;
            }

            $db = NULL;
            echoResponse(200, $response);
        });


$app->post('/users/password/reset', function() use($app) {
            // check for required params
            $json = $app->request->getBody();
            $data = json_decode($json, true);
            $resetcode = $data['resetcode'];
            $password = $data['password'];

            $response = array();

            $db = new DbHandler();
            $res = $db->resetPassword($resetcode, $password);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['message'] = 'Password reset successfully. You can now login in with your new password!';
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['message'] = 'An error occurred while resetting password';
                echoResponse(200, $response);
            }

            $db = NULL;
        });


// Calls that require authentication

$app->get('/events', 'authenticate', function() use($app) {
    $response = array();
    $db = new DbHandler();

    $results   = $db->getAllEvents();

    if ($results) {
        $response['success']    = true;
        $response['username'] = $app->username;
        $response['results']  = $results;
    } else {
        $response['error'] = true;
        $response['results'] = array();
        $response['message'] = 'No events found!';
    }

    echoResponse(200, $response);

    $db = NULL;
});


 $app->get('/users/preferences', 'authenticate', function() use($app) {
 		$response = array();
  	$db = new DbHandler();

      // fetch task
      $result = $db->getPermissionsByUsername($app->username);

      $db->registerAPICall( $app->username, 'preferences', 'get', json_encode($result));

      if ($result != NULL) {
          $response['error'] 				    = false;
          $response['success']                = true;
          $response['username'] 			    = $app->username;
          $response['like_my_post']           = (!empty($result['like_my_post']) && $result['like_my_post'] == 'yes');
          $response['comment_my_post']        = (!empty($result['comment_my_post']) && $result['comment_my_post'] == 'yes');
          $response['comment_my_frontdesk']   = (!empty($result['comment_my_frontdesk']) && $result['comment_my_frontdesk'] == 'yes');
          $response['comment_my_incident']    = (!empty($result['comment_my_incident']) && $result['comment_my_incident'] == 'yes');
          $response['comment_my_maintenance'] = (!empty($result['comment_my_maintenance']) && $result['comment_my_maintenance'] == 'yes');
          $response['comment_my_reservation'] = (!empty($result['comment_my_reservation']) && $result['comment_my_reservation'] == 'yes');
          $response['comment_my_marketplace'] = (!empty($result['comment_my_marketplace']) && $result['comment_my_marketplace'] == 'yes');
          $response['send_external_email']    = (!empty($result['send_external_email']) && $result['send_external_email'] == 'yes');
          echoResponse(200, $response);
      } else {
          $response['error'] = true;
          $response['message'] = "The requested resource doesn't exists";
          echoResponse(404, $response);
      }

 });

 $app->put('/users/preferences', 'authenticate', function() use($app) {

      $json = $app->request->getBody();
      $data = json_decode($json, true);

      $db = new DbHandler();
      $res = $db->updateUserPreferences($app->username, $data);

 			$db->registerAPICall($app->username, 'permissions', 'put', $json);

      if ($res) {
          $response['error'] 		= false;
          $response['username'] 	= $app->username;
          $response['message'] 	= "Permissions updated successfully!";
          echoResponse(201, $response);
      } else {
          $response['error'] 		= true;
          $response['username'] 	= $app->username;
          $response['message'] 	= "An error occurred while updating permissions. Try again later!";
          echoResponse(200, $response);
      }

      $db = null;
  });

$app->run();

?>