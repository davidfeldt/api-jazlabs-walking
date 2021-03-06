<?php

require '../../vendor/autoload.php';
require_once 'include/DbHandler.php';

use \Firebase\JWT\JWT;
use \Slim\Slim;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use \SendGrid\Mail\Mail;
use Slim\Views\PhpRenderer;
use Pusher\Pusher;

$dotenv = new Dotenv\Dotenv('../../');
$dotenv->load();
$dotenv->required('DB_USERNAME', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME')->notEmpty();
$dotenv->required('PUSHER_APP_ID', 'PUSHER_APP_KEY', 'PUSHER_APP_SECRET','PUSHER_APP_CLUSTER')->notEmpty();
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
	    "iss" 			     => "https://walking.jazlabs.xyz",
	    "aud" 			     => "http://walking.jazlabs.xyz",
	    "iat" 			     => time(),
	    "nbf" 			     => time(),
			"username" 		   => $username,
      "registrantId"   => $result['registrantId'],
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
            $app->registrantId  = $decoded->registrantId;
            $app->email         = $decoded->email;
            $app->mobilephone   = $decoded->mobilephone;

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

	$sPhone = trim($sPhone,' ()-+');
	if(strlen($sPhone) != 10) return "Error";

	$sArea = substr($sPhone,0,3);
	$sPrefix = substr($sPhone,3,3);
	$sNumber = substr($sPhone,6,4);
	$sPhone = "(".$sArea.") ".$sPrefix."-".$sNumber;
	return($sPhone);
}

// pusher auth

$app->post('/pusher/auth', 'authenticate', function() use($app) {

    $pusher = new Pusher( $_ENV['PUSHER_APP_KEY'], $_ENV['PUSHER_APP_SECRET'], $_ENV['PUSHER_APP_ID'], array('cluster' => $_ENV['PUSHER_APP_CLUSTER'], 'useTLS' => true) );

    $json = $app->request->getBody();
    // pusher sends data in x-www-form-urlencoded so don't use json for the post vars
    // $data = json_decode($json, true);
    // $channel_name = $data['channel_name'];
    // $socket_id = $data['socket_id'];
    $channel_name = $app->request()->post('channel_name');
    $socket_id    = $app->request()->post('socket_id');

    if ($app->username) {
        header('Content-Type: application/json', true, 200);
        echo $pusher->socket_auth($channel_name, $socket_id);
    } else {
        header('', true, 403);
        echo "Forbidden";
    }

});

$app->post('/pusher/authPresence', 'authenticate', function() use($app) {

    $pusher = new Pusher( $_ENV['PUSHER_APP_KEY'], $_ENV['PUSHER_APP_SECRET'], $_ENV['PUSHER_APP_ID'], array('cluster' => $_ENV['PUSHER_APP_CLUSTER'], 'useTLS' => true) );

    $json = $app->request->getBody();
    // pusher sends data in x-www-form-urlencoded so don't use json for the post vars
    // $data = json_decode($json, true);
    // $channel_name = $data['channel_name'];
    // $socket_id = $data['socket_id'];
    $channel_name = $app->request()->post('channel_name');
    $socket_id    = $app->request()->post('socket_id');

    if ($app->username) {
        header('Content-Type: application/json');
        echo $pusher->presence_auth($channel_name, $socket_id, $app->username);
    } else {
        header('', true, 403);
        echo "Forbidden";
    }

});


// dummy response

$app->get('/', function() {

	$response['success'] = true;
	$response['message'] = 'Walking App Platform v1';

	echoResponse(200, $response);

});

// login using username and MFA via phone or email.

$app->post('/users/auth', function() use($app) {
    // body passed as JSON

    $json = $app->request->getBody();
		$data = json_decode($json, true);
		$username = $data['username'];

    $response = array();

    $db = new DbHandler();
    $result = $db->checkUsername($username);

    if ($result == 'valid') {
      $profile = $db->getProfileByUsername($username);
      $app->username = $username;
      $response = array (
        'success'		      => true,
        'error'           => false,
        'username'        => $profile['username'],
      );
    } else {
    	$response['error'] 		= true;
      $response['success']  = false;
      $response['message'] 	= 'No such username!';
    }

		  $db = NULL;
    echoResponse(200, $response);
  });


$app->get('/calendars/marked-dates', 'authenticate', function() use($app) {
	    date_default_timezone_set($_ENV['TIMEZONE']);
      $days = $_ENV['CALENDAR_PERIOD'];
	    $defaultStart = date('Y-m-01', strtotime('- '.$days.' DAYS'));
	    $defaultEnd = date('Y-m-t', strtotime('+ 365 DAYS'));
	    $response = array();

	    $db = new DbHandler();

	    $error = false;
	    $response['error'] = false;
	    $response['success'] = true;
	    $response['results'] = $db->getCalendarMarkedDates($app->registrantId, $defaultStart,$defaultEnd);

	    echoResponse(200, $response);

	    $db = NULL;
	});

$app->get('/calendar-items/:date', 'authenticate', function($date) use($app) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $response = array();

    $db = new DbHandler();

    $error = false;
    $response['error'] = false;
    $response['success'] = true;
    $response['items'] = $db->getWalksForCalendar($app->registrantId, $date);

    echoResponse(200, $response);

    $db = NULL;
});


  $app->post('/users/signup', function() use($app) {
      // body passed as JSON

      $json = $app->request->getBody();
  		$data = json_decode($json, true);
  		$firstName = !empty($data['firstName']) ? ucwords($data['firstName']) : '';
  		$lastName = !empty($data['lastName']) ? ucwords($data['lastName']) : '';
  		$email = !empty($data['email']) ? strtolower(trim($data['email'])) : '';
  		$title = !empty($data['title']) ? ucwords(trim($data['title'])) : '';
  		$company = !empty($data['company']) ? ucwords(trim($data['company'])) : '';
  		$mobilephone = !empty($data['mobilephone']) ? formatPhoneNumber($data['mobilephone']) : '';
  		$username = !empty($data['username']) ? $data['username'] : '';

      $payload = array(
        'firstName'   => $firstName,
        'lastName'    => $lastName,
        'email'       => $email,
        'title'       => $title,
        'company'     => $company,
        'mobilephone' => $mobilephone,
        'username'    => $username,
      );

      $response = array();

      $db = new DbHandler();
      $response = $db->addUser($payload);

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


$app->post('/users/verify-account', function() use($app) {
    // check for required params
    $json = $app->request->getBody();
    $data = json_decode($json, true);
    $verifyCode = $data['verifyCode'];
    $username = strtolower($data['username']);

    $response = array();

    $db = new DbHandler();


    $res = $db->verifyAccount($verifyCode, $username);

    if ($res) {
        $profile = $db->getProfileByUsername($username);
        $response = array(
          'success'		      => true,
          'error'           => false,
          'verified'        => $profile['verified'] == '1',
          'username'        => $profile['username'],
          'token'			      => generateJWT($username),
          "fullName"        => $profile['fullName'],
          "registrantId"    => $profile['registrantId'],
          "email"           => $profile['email'],
          "mobilephone"     => $profile['mobilephone'],
          "title"           => $profile['title'],
          "company"         => $profile['company'],
          "profileVisible"  => $profile['profileVisible'] == 1
        );
    } else {
        $response['error'] = true;
        $response['username'] = $username;
        $response['verifyCode'] = $verifyCode;
        $response['message'] = 'An error occurred while verifying your account. Try again later.';
    }

    $db = NULL;
    echoResponse(200, $response);
});

$app->get('/users/verifications/:username', function($username) use($app) {
    $response = array();
    $db = new DbHandler();

    $response = $db->sendVerificationCode($username);

    echoResponse(200, $response);

    $db = NULL;
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

$app->get('/people', 'authenticate', function() use($app) {
    $response = array();
    $db = new DbHandler();

    $search_term    = $app->request()->get('search_term');
    $page           = $app->request()->get('page');

    if (!isset($search_term)) {
      $search_term = '';
    }

    if (!isset($page) || $page < 1) { $page = 1;}
    $limit = $_ENV['LIMIT'];
    $start = ($page - 1) * $limit;

    $lastCount = $start + $limit;
    $maxCount  = $db->numberOfPeopleWhoAreRegistedForMyEvents($app->registrantId, $search_term);
    $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;

    $people = $db->getPeopleWhoAreRegistedForMyEvents($app->registrantId, $search_term, $page);

    if ($people) {
        $response['success'] = true;
        $response['error'] = false;
        $response['nextPage'] = $nextPage;
        $response['page']     = $page;
        $response['search_term'] = $search_term;
        $response['start']       = $start;
        $response['lastCount']       = $lastCount;
        $response['maxCount']       = $maxCount;
        $response['results'] = $people;

        $response['message'] = 'People found';
    } else {
        $response['error'] = true;
        $response['success'] = false;
        $response['results'] = array();
        $response['message'] = 'No people found';
    }


    echoResponse(200, $response);

    $db = NULL;
});

$app->get('/walks', 'authenticate', function() use($app) {
    $response = array();
    $db = new DbHandler();

    $page = $app->request()->get('page');
    if (!isset($page) || $page < 1) { $page = 1;}

    $limit = $_ENV['LIMIT'];
    $start = ($page - 1) * $limit;

    $lastCount = $start + $limit;
    $maxCount  = $db->numberOfWalks($app->registrantId);
    $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;

    $results   = $db->getAllWalks($app->registrantId, $page);

    if ($results) {
        $response['success']    = true;
        $response['username'] = $app->username;
        $response['results']  = $results;
        $response['nextPage'] = $nextPage;
    } else {
        $response['error'] = true;
        $response['results'] = array();
        $response['message'] = 'No events found!';
    }

    echoResponse(200, $response);

    $db = NULL;
});



$app->get('/announcements', 'authenticate', function() use($app) {
    $response = array();
    $db = new DbHandler();

    $search_term    = $app->request()->get('search_term');
    $page           = $app->request()->get('page');

    if (!isset($search_term)) {
      $search_term = '';
    }

    if (!isset($page) || $page < 1) { $page = 1;}
    $limit = $_ENV['ANNOUNCEMENTS_LIMIT'];
    $start = ($page - 1) * $limit;

    $lastCount = $start + $limit;
    $maxCount  = $db->numberOfAnnouncements($app->registrantId, $search_term);
    $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;

    $results   = $db->getMyAnnouncements($app->registrantId, $search_term, $page);

    if ($results) {
        $response['success']  = true;
        $response['username'] = $app->username;
        $response['results']  = $results;
        $response['nextPage'] = $nextPage;
    } else {
        $response['error'] = true;
        $response['results'] = array();
        $response['message'] = 'No announcements found!';
    }

    echoResponse(200, $response);

    $db = NULL;
});


// add new walk
$app->post('/walks', 'authenticate', function() use($app) {
  $response = array();
  date_default_timezone_set($_ENV['TIMEZONE']);

  $db = new DbHandler();

  $res = $db->startWalk($app->registrantId);

  if ($res) {
    $walk                  = $db->getWalk($app->registrantId, $res);
    $response['success']   = true;
    $response['error']     = false;
    $response['message']   = 'Walk #' . $walk['walkId'] . ' has started. Get moving!';
    $response['walkId']    = $walk['walkId'];
    $response['walkStarted'] = $walk['startDate'];
  } else {
    $response['success']  = false;
    $response['error']    = true;
    $response['message']  = 'Error starting walk. Try again later!';
    $response['walkId']   = $res;
  }

  echoResponse(200, $response);

  $db = NULL;
});

$app->put('/walks/:walkId', 'authenticate', function($walkId) use($app) {
   $response = array();

   $json = $app->request->getBody();
   $data = json_decode($json, true);
   $coordinates = array_key_exists('coordinates', $data) ? $data['coordinates'] : '';

   $db = new DbHandler();

   $res = $db->endWalk($app->registrantId, $walkId, $coordinates);

   if ($res) {
       $walk                  = $db->getWalk($app->registrantId, $walkId);
       $response['error']     = false;
       $response['success']   = true;
       $response['message']   = 'Your walk has ended! Congrats!';
       $response['walkEnded'] = $walk['endDate'];
       $response['duration']  = $walk['duration'];
       echoResponse(200, $response);
   } else {
       $response['error']   = true;
       $response['message'] = "The requested resource doesn't exists";
       echoResponse(404, $response);
   }

});


 $app->get('/users/profiles', 'authenticate', function() use($app) {
 		$response = array();
  	$db = new DbHandler();
    $profile = $db->getProfileByUsername($app->username);

    if ($profile != NULL) {
        $response['error']        = false;
        $response['success']      = true;
        $response['username']     = $app->username;
        $response['profile']      = $profile;
        echoResponse(200, $response);
    } else {
        $response['error'] = true;
        $response['message'] = "The requested resource doesn't exists";
        $response['profile'] = array();
        echoResponse(404, $response);
    }

 });

 $app->put('/users/profiles', 'authenticate', function() use($app) {
 		$response = array();
  	$db = new DbHandler();
    $json = $app->request->getBody();
    $data = json_decode($json, true);

    $profile = $db->updateProfile($app->username, $data);

    if ($profile != NULL) {
        $response['error']    = false;
        $response['success']  = true;
        $response['username'] = $app->username;
        $response['profile']  = $profile;
        echoResponse(200, $response);
    } else {
        $response['error'] = true;
        $response['message'] = "The requested resource doesn't exists";
        $response['profile'] = array();
        echoResponse(404, $response);
    }

 });

 $app->put('/users/permissions', 'authenticate', function() use($app) {
 		$response = array();
  	$db = new DbHandler();
    $json = $app->request->getBody();
    $data = json_decode($json, true);

    $permissions = $db->updatePermissions($app->registrantId, $data);

    if ($permissions != NULL) {
        $response['error']    = false;
        $response['success']  = true;
        $response['username'] = $app->username;
        $response['permissions']  = $permissions;
        echoResponse(200, $response);
    } else {
        $response['error'] = true;
        $response['message'] = "The requested resource doesn't exists";
        $response['profile'] = array();
        echoResponse(404, $response);
    }

 });

$app->run();

?>
