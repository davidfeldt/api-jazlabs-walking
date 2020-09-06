<?php

require '../../vendor/autoload.php';

require_once 'include/DbHandler.php';

use \Firebase\JWT\JWT;
use \Slim\Slim;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use Pusher\Pusher;


$dotenv = new Dotenv\Dotenv('../../');
$dotenv->load();
$dotenv->required('DB_USERNAME', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME')->notEmpty();
$dotenv->required('PUSHER_APP_ID', 'PUSHER_APP_KEY', 'PUSHER_APP_SECRET')->notEmpty();
$dotenv->required('TWILIO_SID', 'TWILIO_TOKEN', 'TWILIO_NUMBER')->notEmpty();
$dotenv->required('JWT_SECRET', 'JWT_LEEWAY')->notEmpty();
$dotenv->required('MAILGUN_API_KEY')->notEmpty();

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
	$user 		= $db->getProfileByUsername($username);

	$payload 	= array(
				    "iss" 			=> "https://myjazlife.com",
				    "aud" 			=> "http://myjazlife.com",
				    "iat" 			=> time(),
				    "nbf" 			=> time(),
	    			"username" 		=> $username,
	          "firstname"		=> $user['firstname'],
	          "lastname"      => $user['lastname'],
	          "fullname"      => $user['fullname'],
	          "unit"     		=> $user['unit'],
	          "bid"    		=> (int)$user['bid'],
	           "privacy" 		=> $user['privacy'],
	           "resident_type"	=> $user['resident_type'],
	           "avatar"        => $_ENV['HTTP_SERVER'].$user['profilepic'],
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
            $app->username 		= $decoded->username;
            $app->firstname     = $decoded->firstname;
            $app->lastname      = $decoded->lastname;
            $app->fullname      = $decoded->fullname;
            $app->unit     		= $decoded->unit;
            $app->bid    		= $decoded->bid;
            $app->privacy 		= !empty($decoded->privacy) ? $decoded->privacy : 'p';
            $app->resident_type	= !empty($decoded->resident_type) ? $decoded->resident_type : '';
            $app->avatar        = !empty($decoded->profilepic) ? $decoded->profilepic : '';
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
	$response['message'] = 'JazLife Community Platform v3';

	echoResponse(200, $response);

});

// login

// Pusher
$app->post('/pusher/auth', 'authenticate', function() use($app) {

    $pusher = new Pusher( $_ENV['PUSHER_APP_KEY'], $_ENV['PUSHER_APP_SECRET'], $_ENV['PUSHER_APP_ID'], array('cluster' => $_ENV['PUSHER_APP_CLUSTER']) );

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

    $pusher = new Pusher( $_ENV['PUSHER_APP_KEY'], $_ENV['PUSHER_APP_SECRET'], $_ENV['PUSHER_APP_ID'], array('cluster' => $_ENV['PUSHER_APP_CLUSTER']) );

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

$app->post('/login', function() use($app) {
            // check for required params
            verifyRequiredParams(array('username'));

            $response = array();

            // reading post params
        	parse_str($app->request()->getBody(), $request_params);

            $username = $request_params['username'];

    		$password = $request_params['password'];

            $response = array();

            $db = new DbHandler();
            $result = $db->checkLogin($username,$password);

            $db-> registerAPICall($username, 'login', 'post', $result);

            if ($result == 'valid') {
                // get the user by username

                $app->username = $username;

                $response = array (
                	'success'		=> true,
                	'token'			=> generateJWT($username)
                );

            }

            if ($result == 'not_username' || $result == 'not_password') {
            	$response['error'] 		= true;
                $response['message'] 	= 'Incorrect username or password';
            }

 			$db = NULL;
            echoResponse(200, $response);
        });


$app->post('/users/auth', function() use($app) {
            // body passed as JSON

            $json = $app->request->getBody();
    		$data = json_decode($json, true);
    		$username = $data['username'];
    		$password = $data['password'];

            $response = array();

            $db = new DbHandler();
            $result = $db->checkLogin($username,$password);

            $db-> registerAPICall($username, 'login', 'post', $result);

            if ($result == 'valid') {
                // get the user by username

                $app->username = $username;
                $profile        = $db->getProfileByUsername($username);

                $response = array (
                	'success'		=> true,
                	'token'			=> generateJWT($username),
                    'username'      => $username,
                    'avatar'        => $_ENV['HTTP_SERVER'].$profile['profilepic'],
                    'fullname'      => $profile['fullname']

                );

            }

            if ($result == 'not_username' || $result == 'not_password') {
            	$response['error'] 		= true;
                $response['message'] 	= 'Incorrect username or password';
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

// File uploads

$app->get('/counts/announcements', 'authenticate', function() use($app) { 
    $response = array();

    $db = new DbHandler();

    $new =  $db->newAnnouncementsCount($app->username, $app->property_id);

    $response['success']  = true;
    $response['error']    = false;
    $response['username'] = $app->username;
    $response['new']      = $new;

    echoResponse(200, $response);

    $db = NULL;
  });

$app->get('/counts/notifications', 'authenticate', function() use($app) {
  $response = array();

  $db = new DbHandler();

  $count =  (int)$db->newNotificationsCount($app->username);

  if ($count !== null) {
      $response['success']  = true;
      $response['error']    = false;
      $response['username'] = $app->username;
      $response['count']    = $count;
  } else {
      $response['success']  = false;
      $response['error']    = true;
      $response['count']    = '';
      $response['message'] = 'Error getting notifications count!';
  }

  echoResponse(200, $response);

  $db = NULL;
});

$app->post('/files', 'authenticate', function() use($app) {

            $response = array();

            $db = new DbHandler();
            $res = $db->addImage($app->username);

            if ($res) {
                $response['error'] = false;
                $response['message'] = "File uploaded successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "An error occurred while uploading file";
                echoResponse(200, $response);
            }
        });

$app->post('/profilephotos', 'authenticate', function() use($app) {

            $response = array();

            $db = new DbHandler();
            $res = $db->addProfilePhoto($app->username);

            if ($res) {
                $response['error'] = false;
                $response['message'] = "File uploaded successfully!";
                $response['profilepic'] = $_ENV['HTTP_IMAGE'].'profile/'.$res;
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "An error occurred while uploading file";
                echoResponse(200, $response);
            }
        });

// Wall Posts

$app->post('/posts/:id', 'authenticate', function($id) use($app) {

    $response = array();

            $json = $app->request->getBody();
            $data = json_decode($json, true);

            $comment = $data['comment'];

            $db = new DbHandler();
            $res = $db->addPostComment($app->username, $id, $comment);

            $db->registerAPICall( $app->username, 'posts/comments', 'post', $json);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['username'] = $app->username;
                $response['message'] = "Comment posted successfully!";
                $response['results'] = $db->getPostComments($id);
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['username'] = $app->username;
                $response['message'] = "An error occurred while posting comment";
                $response['results'] = array();
                echoResponse(200, $response);
            }
        });



$app->post('/posts', 'authenticate', function() use($app) {
            // check for required params
            // verifyRequiredParams(array('message'));

            $response = array();

            $json = $app->request->getBody();
            $data = json_decode($json, true);
            $message = $data['message'];
            $image   = $data['image'];

            $db = new DbHandler();

            $res = $db->addPost($app->username, $message, $image);

            // $db->registerAPICall( $app->username, 'posts', 'post', $res);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['req'] = $message;
                $response['username'] = $app->username;
                $response['message'] = "Message posted successfully!";
                $response['results'] = $db->getAllPosts($app->username, 1);;
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['username'] = $app->username;
                $response['message'] = "An error occurred while posting";
                $response['results'] = array();
                $response['req'] = $message;
                echoResponse(200, $response);
            }

        });

$app->post('/posts/like/:id', 'authenticate', function($id) use($app) {

            $response = array();

            $db = new DbHandler();
            $res = $db->likePost($app->username, $app->bid, $id);

            $db->registerAPICall( $app->username, 'posts/like/'.$id, 'post', json_encode($res));

            if ($res) {
                $response['success'] = true;
                $response['username'] = $app->username;
                $response['results'] = $res;
                $response['message'] = "Liked successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['username'] = $app->username;
                $response['message'] = "An error occurred while liking post";
                echoResponse(200, $response);
            }
        });

$app->post('/posts/report/:id', 'authenticate', function($id) use($app) {

            $response = array();

            $db = new DbHandler();
            $res = $db->reportPost($app->username, $app->bid, $id);

 			$db->registerAPICall( $app->username, 'posts/report/'.$id, 'post', json_encode($res));

            if ($res) {
                $response['success'] = true;
                $response['username'] = $app->username;
                $response['results'] = $res;
                $response['message'] = "Reported successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['username'] = $app->username;
                $response['message'] = "An error occurred while reporting post";
                echoResponse(200, $response);
            }
        });

$app->get('/posts', 'authenticate', function() use($app) {
            $response = array();

            $db = new DbHandler();

            $page = $app->request()->get('page');

            if (!isset($page) || $page < 1) { $page = 1;}

            $results = $db->getAllPosts($app->username, $page);

            if ($results) {

                $response['error'] 	= false;
                $response['success'] = true;
                $response['username'] = $app->username;
                $response['results']  = $results;
            } else {
                $response['error'] = true;
                $response['message'] = 'Error loading community feed';
            }

			$db->registerAPICall( $app->username, 'posts', 'get', '1');

            echoResponse(200, $response);

            $db = NULL;
        });

$app->get('/posts/:id', 'authenticate', function($id) use($app) {
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getPost($app->username, $id);

 			$db->registerAPICall( $app->username, 'posts/'.$id, 'get', $result);

            if ($result != NULL) {
                $response['error'] 		= false;
                $response['id'] 		= $result['id'];
                $response['bid'] 		= $result['bid'];
                $response['username'] 	= $result['username'];
                $response['fullname']	= $result['fullname'];
                $response['message']	= $result['message'];
                $response['date_added'] 		= $db->dateTimeDiff($result['date_added']);
                $response['type']		= $result['type'];
                $response['comments']	= $result['comments'];
                echoResponse(200, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "The requested resource doesn't exists";
                echoResponse(404, $response);
            }
        });

$app->get('/posts/search/:q', 'authenticate', function($q) use($app) {
			$response = array();

            $db 	= new DbHandler();

            $page 	= $app->request()->get('page');
            $page 	= (isset($page)) ? $page : 1;

            if (!isset($q)) {
            	$response["error"] = true;
                $response["message"] = "Please enter search query!";
            	echoResponse(200, $response);
            } else {

            	$response['error'] 	= false;
            	$response['username'] = $app->username;
            	$response['posts']  = $db->getSearchPosts($app->username,$page, $q);

				$db->registerAPICall( $app->username, 'posts/search/'.$q, 'get', '1');

            	echoResponse(200, $response);

            	$db = NULL;
			}

});

$app->delete('/posts/:id', 'authenticate', function($id) use($app) {

            $db = new DbHandler();
            $response = array();
            $result = $db->deletePost($app->username, $id);

            $db->registerAPICall( $app->username, 'posts/'.$id, 'delete', 1);

            if ($result) {
                $response['error'] = false;
                $response['success'] = true;
                $response['message'] = "Post deleted successfully";
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = "Post failed to delete. Please try again!";
            }
            echoResponse(200, $response);
        });

// maintenance requests

$app->post('/requests', 'authenticate', function() use($app) {

            // check for required params
            //verifyRequiredParams(array('description', 'enterpermission', 'urgency', 'instruction', 'category','date_noticed'));

            $response 				= array();
            $requestData  			= array();

            $json 					= $app->request->getBody();
            $data 					= json_decode($json, true);

            $requestData['status']			= 's';
            $requestData['description']		= $data['description'];
            $requestData['enterPermission'] = $data['enterPermission'];
            $requestData['urgency'] 		= $data['urgency'];
            $requestData['instruction'] 	= $data['instruction'];
            $requestData['category_id']		= $data['category_id'];
            $requestData['dateNoticed']		= $data['dateNoticed'];
            $requestData['image']			= $data['image'];

            $db = new DbHandler();
            $res = $db->addMaintenanceRequest($app->username, $requestData);

 			$db->registerAPICall( $app->username, 'requests', 'post', $res);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['message'] = "Maintenance request posted successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "An error occurred while posting maintenance request";
                echoResponse(200, $response);
            }
        });


$app->post('/requests/comments/:id', 'authenticate', function($id) use($app) {

            $response = array();

            $json = $app->request->getBody();
            $data = json_decode($json, true);

            $comment = $data['comment'];

            $db = new DbHandler();
            $res = $db->addComment($app->username, $id, $comment, 'maintenance');

            $db->registerAPICall( $app->username, 'requests/comments', 'post', $json);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['username'] = $app->username;
                $response['message'] = "Comment posted successfully!";
                $response['results'] = $db->getMaintenanceComments($id);
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['username'] = $app->username;
                $response['message'] = "An error occurred while posting comment";
                $response['results'] = array();
                echoResponse(200, $response);
            }
        });



$app->put('/requests/:id', 'authenticate', function($id) use($app) {

            // check for required params
            verifyRequiredParams(array('description', 'enterpermission', 'urgency', 'instruction', 'category','status','date_noticed'));

            // reading post params

            $date_created 		= date('Y-m-d');
            $description 		= $app->request->put('description');
            $enterpermission 	= $app->request->put('enterpermission');
            $urgency 			= $app->request->put('urgency');
            $instruction 		= $app->request->put('instruction');
            $category 			= $app->request->put('category');
            $status 			= $app->request->put('status');
            $date_noticed 		= $app->request->put('date_noticed');

            $db = new DbHandler();
            $res = $db->updateMaintenanceRequest($id, $app->username, $date_created, $description, $enterpermission, $urgency, $instruction, $category, $status, $date_noticed);

 			$db->registerAPICall( $app->username, 'requests/'.$id, 'put', $res);

            if ($res) {
                $response['error'] = false;
                $response['message'] = "Maintenance request updated successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "An error occurred while updating maintenance request";
                echoResponse(200, $response);
            }
        });


$app->get('/requests', 'authenticate', function() use($app) {
            $response = array();
            $db = new DbHandler();

			$page = $app->request()->get('page');

            if (!isset($page) || $page < 1) { $page = 1;}

            $results = $db->getAllMaintenanceRequests($app->username,$page);

            if ($results) {
                $response['success'] = true;
                $response['results'] = $results;
            } else {
                $response['error'] = true;
                $response['message'] = 'Could not load maintenance requests.';
            }

            $db->registerAPICall( $app->username, 'requests', 'get', '1');

            echoResponse(200, $response);

            $db = NULL;
        });

$app->get('/requests/comments/:id', 'authenticate', function($id) use($app) {
			$response = array();
            $db = new DbHandler();

            $result = $db->getMaintenanceComments($id);

 			$db->registerAPICall($app->username, 'requests/comments/'.$id, 'get', json_encode($result));

            if ($result != NULL) {
                $response['error'] 		= false;
                $response['success'] 	= true;
                $response['results']    = $result;

                echoResponse(200, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "The requested resource doesn't exists";
                $response['results'] = $response;
                echoResponse(404, $response);
            }
        });

$app->delete('/requests/:id', 'authenticate', function($id) use($app) {

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteMaintenanceRequest($app->username, $id);

            $db->registerAPICall( $app->username, 'requests/'.$id, 'delete', 1);

            if ($result) {
                // task deleted successfully
                $response['error'] = false;
                $response['success'] = true;
                $response['message'] = "Maintenance request deleted successfully";
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = "Maintenance request failed to delete. Please try again!";
            }
            echoResponse(200, $response);
        });

// Reservations

$app->get('/reservations/comments/:id', 'authenticate', function($id) use($app) {
            $response = array();
            $db = new DbHandler();

            $result = $db->getReservationComments($id);

            $db->registerAPICall($app->username, 'reservations/comments/'.$id, 'get', json_encode($result));

            if ($result != NULL) {
                $response['error']      = false;
                $response['success']    = true;
                $response['results']    = $result;

                echoResponse(200, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "The requested resource doesn't exists";
                $response['results'] = $response;
                echoResponse(404, $response);
            }
        });

$app->post('/reservations/timeslots', 'authenticate', function() use($app) {
            $response = array();

            $json = $app->request->getBody();
            $data = json_decode($json, true);

            $db = new DbHandler();

            $result = $db->getAvailableTimeSlots($app->bid, $data);

            $db->registerAPICall($app->username, 'reservations/timeslots/', 'get', $json);

            if ($result != NULL) {
                $response['error']      = false;
                $response['success']    = true;
                $response['timeslots']  = $result;

                echoResponse(200, $response);
            } else {
                $response['error']      = true;
                $response['message']    = "No available timeslots found. Choose alternative dates.";
                $response['results']    = $response;
                echoResponse(404, $response);
            }
        });


$app->get('/reservations', 'authenticate', function() use($app) {
            $response = array();
            $db = new DbHandler();

            $page = $app->request()->get('page');

            if (!isset($page) || $page < 1) { $page = 1;}

            $results = $db->getAllReservations($app->username,$page);

            if ($results) {
                $response['success'] = true;
                $response['results'] = $results;
            } else {
                $response['error'] = true;
                $response['message'] = 'No reservations at present.';
            }

            $db->registerAPICall( $app->username, 'requests', 'get', '1');

            echoResponse(200, $response);

            $db = NULL;
        });

$app->post('/reservations', 'authenticate', function() use($app) {

            $response = array();

            $json = $app->request->getBody();
            $data = json_decode($json, true);

            // facility_id, resource_id, startDate, endDate, timeslots, all car data if parking

            $db = new DbHandler();
            $res = $db->addReservation($app->username, $data);

            $db->registerAPICall( $app->username, 'reservations', 'post', $json);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['username'] = $app->username;
                $response['message'] = "Reservation added successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['username'] = $app->username;
                $response['message'] = "An error occurred while adding reservation";
                $response['results'] = array();
                echoResponse(200, $response);
            }
        });

$app->post('/reservations/comments/:id', 'authenticate', function($id) use($app) {

            $response = array();

            $json = $app->request->getBody();
            $data = json_decode($json, true);

            $comment = $data['comment'];

            $db = new DbHandler();
            $res = $db->addComment($app->username, $id, $comment, 'reservation');

            $db->registerAPICall( $app->username, 'reservations/comments', 'post', $json);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['username'] = $app->username;
                $response['message'] = "Comment posted successfully!";
                $response['results'] = $db->getReservationComments($id);
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['username'] = $app->username;
                $response['message'] = "An error occurred while posting comment";
                $response['results'] = array();
                echoResponse(200, $response);
            }
        });

$app->delete('/reservations/:id', 'authenticate', function($id) use($app) {

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteReservation($app->username, $id);

            $db->registerAPICall( $app->username, 'reservations/'.$id, 'delete', 1);

            if ($result) {
                // task deleted successfully
                $response['error'] = false;
                $response['success'] = true;
                $response['message'] = "Reservation deleted successfully";
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = "Reservation failed to delete. Please try again!";
            }
            echoResponse(200, $response);
        });


// Front Desk Instructions

$app->post('/instructions', 'authenticate', function() use($app) {

            $response               = array();

            $json                   = $app->request->getBody();
            $data                   = json_decode($json, true);

            $db  = new DbHandler();
            $res = $db->addFrontdeskInstruction($app->username, $data);

            $db->registerAPICall( $app->username, 'instructions', 'post', json_encode($res));

            if ($res) {
                $response['error']  = false;
                $response['success'] = true;
                $response['message'] = "Frontdesk instruction added successfully!";
                $response['request'] = $data;
                $response['results'] = $res;
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "An error occurred while adding frontdesk instruction";
                $response['request'] = $data;
                $response['results'] = $res;
                echoResponse(200, $response);
            }
        });

$app->post('/instructions/comments/:id', 'authenticate', function($id) use($app) {

            $response = array();

            $json = $app->request->getBody();
            $data = json_decode($json, true);

            $comment = $data['comment'];

            $db = new DbHandler();
            $res = $db->addComment($app->username, $id, $comment, 'frontdesk');

            $db->registerAPICall( $app->username, 'frontdesk/comments', 'post', $json);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['username'] = $app->username;
                $response['message'] = "Comment posted successfully!";
                $response['results'] = $db->getFrontdeskComments($id);
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['username'] = $app->username;
                $response['message'] = "An error occurred while posting comment";
                $response['results'] = array();
                echoResponse(200, $response);
            }
        });


$app->put('/instructions/:id', 'authenticate', function($id) use($app) {
            // check for required params
            verifyRequiredParams(array('description', 'enterpermission', 'urgency', 'instruction', 'category','status','date_noticed'));
			// reading post params

            $date_created 		= date('Y-m-d');
            $description 		= $app->request->put('description');
            $enterpermission 	= $app->request->put('enterpermission');
            $urgency 			= $app->request->put('urgency');
            $instruction 		= $app->request->put('instruction');
            $category 			= $app->request->put('category');
            $status 			= $app->request->put('status');
            $date_noticed 		= $app->request->put('date_noticed');

            $db = new DbHandler();
            $res = $db->updateFrontDeskInstruction($id, $app->username, $date_created, $description, $startdate, $enddate, $noenddate, $category);

 			$db->registerAPICall( $app->username, 'instructions/'.$id, 'put', $res);

            if ($res) {
                $response['error'] = false;
                $response['message'] = "Front desk instruction updated successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "An error occurred while updating front desk instruction";
                echoResponse(200, $response);
            }
        });


$app->get('/instructions',  'authenticate' , function()  use($app) {
            $response = array();

            $db = new DbHandler();

            $page = $app->request()->get('page');

            if (!isset($page) || $page < 1) { $page = 1;}

            $results = $db->getAllFrontDeskInstructions($app->username,$page);

            if ($results) {
                $response['success'] = true;
                $response['results'] = $results;
            } else {
                $response['error'] = true;
                $response['message'] = 'Could not load frontdesk instructions.';
            }

			$db->registerAPICall( $app->username, 'instructions', 'get', '1');

            echoResponse(200, $response);

            $db = NULL;
        });

$app->get('/instructions/comments/:id', 'authenticate', function($id) use($app) {
            $response = array();
            $db = new DbHandler();

            $result = $db->getFrontdeskComments($id);

            $db->registerAPICall( $app->username, 'instructions/comments/'.$id, 'get', json_encode($result));


            if ($result != NULL) {
                $response['error'] 			= false;
                $response['success']        = true;
                $response['results'] 		= $result;

                echoResponse(200, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "The requested front desk instruction doesn't exists";
                $response['results'] = $response;
                echoResponse(404, $response);
            }
        });

$app->delete('/instructions/:id', 'authenticate', function($id) use($app) {
            $db = new DbHandler();
            $response = array();
            $result = $db->deleteFrontDeskInstruction($app->username, $id);

            $db->registerAPICall( $app->username, 'instructions/'.$id, 'delete', 1);

            if ($result) {
                // task deleted successfully
                $response['error'] = false;
                $response['success'] = true;
                $response['message'] = "Front desk instruction deleted successfully";
            } else {
                // task failed to delete
                $response['error'] = true;
                $response['message'] = "Front desk instruction failed to delete. Please try again!";
            }
            echoResponse(200, $response);
        });

// Marketplace

$app->get('/items/comments/:id', 'authenticate', function($id) use($app) {
            $response = array();
            $db = new DbHandler();

            $result = $db->getMarketplaceComments($id);

            $db->registerAPICall($app->username, 'marketplace/comments/'.$id, 'get', json_encode($result));

            if ($result != NULL) {
                $response['error']      = false;
                $response['success']    = true;
                $response['results']    = $result;

                echoResponse(200, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "The requested resource doesn't exists";
                $response['results'] = $response;
                echoResponse(404, $response);
            }
        });

$app->get('/items', 'authenticate', function() use($app) {
            $response = array();
            $db = new DbHandler();

			$page = $app->request()->get('page');

            if (!isset($page) || $page < 1) { $page = 1;}

            $results = $db->getAllMarketplaceItems($app->bid,$page);

            if ($results) {
                $response['success'] = true;
                $response['results'] = $results;
            } else {
                $response['error'] = true;
                $response['message'] = 'Could not load marketplace items';
            }


            $db->registerAPICall( $app->username, 'items', 'get', '1');

            echoResponse(200, $response);

            $db = NULL;
        });



$app->post('/items', 'authenticate', function() use($app) {

            // check for required params
            //verifyRequiredParams(array('description', 'enterpermission', 'urgency', 'instruction', 'category','date_noticed'));

            $response               = array();
            $requestData            = array();

            $json                   = $app->request->getBody();
            $data                   = json_decode($json, true);

            $requestData['image']           = $data['image'];
            $requestData['title']           = $data['title'];
            $requestData['description']     = $data['description'];
            $requestData['price']           = $data['price'];
            $requestData['type']            = $data['type'];
            $requestData['isAvailable']     = $data['isAvailable'];
            $requestData['category_id']     = $data['category_id'];

            $db = new DbHandler();
            $res = $db->addMarketplaceItem($app->username, $requestData);

            $db->registerAPICall( $app->username, 'items', 'post', 1);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['message'] = "Marketplace item added successfully!";
                $response['request'] = $requestData;
                $response['response'] =  $res;
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "An error occurred while adding marketplace item";
                $response['request'] = $requestData;
                $response['response'] =  $res;
                echoResponse(200, $response);
            }
        });

$app->post('/items/comments/:id', 'authenticate', function($id) use($app) {

            $response = array();

            $json = $app->request->getBody();
            $data = json_decode($json, true);

            $comment = $data['comment'];

            $db = new DbHandler();
            $res = $db->addComment($app->username, $id, $comment, 'marketplace');

            $db->registerAPICall( $app->username, 'items/comments', 'post', $json);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['username'] = $app->username;
                $response['message'] = "Comment posted successfully!";
                $response['results'] = $db->getMarketplaceComments($id);
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['username'] = $app->username;
                $response['message'] = "An error occurred while posting comment";
                $response['results'] = array();
                echoResponse(200, $response);
            }
        });


// Incident Reports

$app->post('/incidents', 'authenticate', function() use($app) {

            $response 				= array();
            $incidentData  			= array();

            $json 					= $app->request->getBody();
            $data 					= json_decode($json, true);

            $incidentData['status']			= 's';
            $incidentData['description']	= $data['description'];
            $incidentData['dateNoticed']	= $data['dateNoticed'];
            $incidentData['timeNoticed'] 	= $data['timeNoticed'];
            $incidentData['category_id']	= $data['category_id'];
            $incidentData['image']			= $data['image'];

            $db = new DbHandler();
            $res = $db->addIncidentReport($app->username, $incidentData);

 			$db->registerAPICall( $app->username, 'incidents', 'post', $res);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['message'] = "Incident report posted successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "An error occurred while posting incident report";
                echoResponse(200, $response);
            }
        });


$app->post('/incidents/comments/:id', 'authenticate', function($id) use($app) {

            $response = array();

            $json = $app->request->getBody();
            $data = json_decode($json, true);
            $comment = $data['comment'];

            $db = new DbHandler();
            $res = $db->addComment($app->username, $id, $comment, 'incident');

            $db->registerAPICall( $app->username, 'incidents/comments', 'post', $json);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['username'] = $app->username;
                $response['message'] = "Comment posted successfully!";
                $response['results'] = $db->getIncidentComments($id);
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['username'] = $app->username;
                $response['message'] = "An error occurred while posting comment";
                $response['results'] = array();
                echoResponse(200, $response);
            }
        });


$app->put('/incidents/:id', 'authenticate', function($id) use($app) {
            // check for required params
            verifyRequiredParams(array('description', 'date_noticed', 'time_noticed', 'category'));
			// reading post params

            $date_created 		= date('Y-m-d');
            $description 		= $request_params['description'];
            $date_noticed 		= $request_params['date_noticed'];
            $time_noticed 		= $request_params['time_noticed'];
            $category 			= $request_params['category'];

            $db = new DbHandler();
            $res = $db->updateIncidentReport($id, $app->username, $date_created, $date_noticed, $time_noticed, $description, $category);

 			$db->registerAPICall( $app->username, 'incidents/'.$id, 'put', $res);

            if ($res) {
                $response['error'] = false;
                $response['message'] = "Incident report updated successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "An error occurred while updating incident report";
                echoResponse(200, $response);
            }
        });


$app->get('/incidents',  'authenticate' , function()  use($app) {
            $response = array();

            $db = new DbHandler();

            $page = $app->request()->get('page');

            if (!isset($page) || $page < 1) { $page = 1;}

            $results = $db->getAllIncidentReports($app->username,$page);

            if ($results) {
                $response['success'] = true;
                $response['results'] = $results;
            } else {
                $response['error'] = true;
                $response['message'] = 'Could not load incident reports.';
            }

			$db->registerAPICall( $app->username, 'incidents', 'get', '1');

            echoResponse(200, $response);

            $db = NULL;
        });

$app->get('/incidents/comments/:id', 'authenticate', function($id) use($app) {
            $response = array();
            $db = new DbHandler();

            $result = $db->getIncidentComments($id);

            $db->registerAPICall( $app->username, 'incidents/comments/'.$id, 'get', json_encode($result));

            if ($result != NULL) {
                $response['error'] 			= false;
                $response['success'] 		= true;
                $response['results'] 		= $result;

                echoResponse(200, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "The requested incident report doesn't exists";
                $response['results'] = $response;
                echoResponse(404, $response);
            }
        });

$app->delete('/incidents/:id', 'authenticate', function($id) use($app) {
            $db = new DbHandler();
            $response = array();
            $result = $db->deleteIncidentReport($app->username, $id);

            $db->registerAPICall( $app->username, 'incidents/'.$id, 'delete', 1);

            if ($result) {
                // task deleted successfully
                $response['error'] = false;
                $response['success'] = true;
                $response['results'] = $result;
                $response['message'] = "Incident report deleted successfully";
            } else {
                // task failed to delete
                $response['error'] = true;
                $response['message'] = "Incident report failed to delete. Please try again!";
            }
            echoResponse(200, $response);
        });



// Messages / Mail

$app->post('/messages', 'authenticate', function() use($app) {
            // check for required params
            $json = $app->request->getBody();
            $data = json_decode($json, true);
            $userTo = $data['userTo'];
            $subject = $data['subject'];
            $message = $data['message'];

            $db = new DbHandler();
            $res = $db->addMessage($app->username, $userTo, $subject, $message);

            $db->registerAPICall( $app->username, 'messages', 'post', $res);

            if ($res) {
                $response['error'] 		= false;
                $response['success']    = true;
                $response['username'] 	= $app->username;
                $response['message'] 	= "Message sent successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] 		= true;
                $response['username'] 	= $app->username;
                $response['message'] 	= "An error occurred while sending message";
                echoResponse(200, $response);
            }
        });

// post message to user with username :id

$app->post('/messages/:id', 'authenticate', function($id) use($app) {
            // check for required params
            $json = $app->request->getBody();
            $data = json_decode($json, true);
            $userTo = $id;
            $subject = $data['subject'];
            $message = $data['message'];

            $db = new DbHandler();
            $res = $db->addMessage($app->username, $userTo, $subject, $message);

            $db->registerAPICall( $app->username, 'messages/'.$id, 'post', $res);

            if ($res) {
                $response['error'] 		= false;
                $response['success']    = true;
                $response['username'] 	= $app->username;
                $response['message'] 	= "Message sent successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] 		= true;
                $response['username'] 	= $app->username;
                $response['message'] 	= "An error occurred while sending message";
                echoResponse(200, $response);
            }
        });

// Post reply to message :id

$app->post('/messages/replies/:id', 'authenticate', function($id) use($app) {
            // check for required params
            $json = $app->request->getBody();
            $data = json_decode($json, true);
            $reply = $data['reply'];

            $response = array();

            $db = new DbHandler();
            $res = $db->addReplyToMessage($app->username, $id, $reply);

 			$db->registerAPICall( $app->username, 'messages/'.$id, 'post', $res);

            if ($res) {
                $response['error'] = false;
                $response['success'] = true;
                $response['username'] = $app->username;
                $response['message'] = "Reply posted successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] = true;
                $response['username'] = $app->username;
                $response['message'] = "An error occurred while posting reply";
                $response['response']= array('id' => $id, 'reply' => $reply);
                echoResponse(200, $response);
            }
        });

$app->get('/messages', 'authenticate', function() use($app) {
			$response = array();
            $db = new DbHandler();

            $page = $app->request()->get('page');

            if (!isset($page) || $page < 1) { $page = 1;}

            $results = $db->getAllMessages($app->username, $page);

            if ($results) {
                $response['success']    = true;
                $response['username'] = $app->username;
                $response['results']  = $results;
            } else {
                $response['error'] = true;
                $response['results'] = array();
                $response['message'] = 'No messages found!';
            }

			$db->registerAPICall( $app->username, 'messages', 'get', '1');

            echoResponse(200, $response);

            $db = NULL;
        });

$app->get('/messages/:id', 'authenticate', function($id) use($app) {
            $response = array();
            $db = new DbHandler();

            $result = $db->getMessage($app->username, $id);

            $db->registerAPICall( $app->username, 'messages/'.$id, 'get', $result);

            if ($result != NULL) {
                $response['error'] 			= false;
                $response['owner'] 			= $result['owner'];
                $response['message_id'] 	= $result['message_id'];
                $response['userTo'] 		= $result['userTo'];
                $response['userFrom'] 		= $result['userFrom'];
                $response['fullname']		= $db->getResidentName($result['userFrom']);
                $response['sentDate']		= $db->dateTimeDiff($result['sentDate']);
                $response['subject']		= $result['subject'];
                $response['message']		= $result['message'];
                $response['status']			= $result['status'];

                echoResponse(200, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "The requested message doesn't exists";
                echoResponse(404, $response);
            }
        });

$app->delete('/messages/:id', 'authenticate', function($id) use($app) {
            $db = new DbHandler();
            $response = array();
            $result = $db->deleteMessage($app->username, $id);

            $db->registerAPICall( $app->username, 'messages/'.$id, 'delete', 1);

            if ($result) {
                // task deleted successfully
                $response['error'] = false;
                $response['success'] = true;
                $response['message'] = "Message deleted successfully";
                $response['username'] 	= $app->username;
            } else {
                // task failed to delete
                $response["error"] 		= true;
                $response['username'] 	= $app->username;
                $response["message"] 	= "Message failed to delete. Please try again!";
            }
            echoResponse(200, $response);
        });

// news

$app->get('/news', 'authenticate', function() use($app) {
        $response = array();
        $db = new DbHandler();

        $page = $app->request()->get('page');

        if (!isset($page) || $page < 1) { $page = 1;}

        $results   = $db->getAllNews($app->bid, $page);

        if ($results) {
            $response['success']    = true;
            $response['username'] = $app->username;
            $response['results']  = $results;
        } else {
            $response['error'] = true;
            $response['results'] = array();
            $response['message'] = 'No news found!';
        }

        $db->registerAPICall( $app->username, 'news', 'get', '1');

        echoResponse(200, $response);

        $db = NULL;
    });

// people

$app->get('/people', 'authenticate', function() use($app) {
        $response = array();
        $db = new DbHandler();

        $page = $app->request()->get('page');

        if (!isset($page) || $page < 1) { $page = 1;}

        $results   = $db->getAllPeople($app->bid, $page);

        if ($results) {
            $response['success']    = true;
            $response['username'] = $app->username;
            $response['results']  = $results;
        } else {
            $response['error'] = true;
            $response['results'] = array();
            $response['message'] = 'No people found!';
        }

        $db->registerAPICall( $app->username, 'people', 'get', '1');

        echoResponse(200, $response);

        $db = NULL;
    });

$app->get('/propertymanagers', 'authenticate', function() use($app) {
        $response = array();
        $db = new DbHandler();

        $page = $app->request()->get('page');

        if (!isset($page) || $page < 1) { $page = 1;}

        $results   = $db->getAllPropertyManagers($app->bid, $page);

        if ($results) {
            $response['success']    = true;
            $response['username'] = $app->username;
            $response['results']  = $results;
        } else {
            $response['error'] = true;
            $response['results'] = array();
            $response['message'] = 'No property managers found!';
        }

        $db->registerAPICall( $app->username, 'propertymanagers', 'get', '1');

        echoResponse(200, $response);

        $db = NULL;
    });

$app->get('/people/boardmembers', 'authenticate', function() use($app) {
        $response = array();
        $db = new DbHandler();

        $page = $app->request()->get('page');

        if (!isset($page) || $page < 1) { $page = 1;}

        $results   = $db->getAllBoardMembers($app->bid, $page);

        if ($results) {
            $response['success']    = true;
            $response['username'] = $app->username;
            $response['results']  = $results;
        } else {
            $response['error'] = true;
            $response['results'] = array();
            $response['message'] = 'No boardmembers found!';
        }

        $db->registerAPICall( $app->username, 'people/boardmembers', 'get', '1');

        echoResponse(200, $response);

        $db = NULL;
    });

$app->get('/people/all', 'authenticate', function() use($app) {
        $response = array();
        $db = new DbHandler();

        $results   = $db->getAllPeopleAutoComplete($app->bid);

        if ($results) {
            $response['success']    = true;
            $response['username'] = $app->username;
            $response['people']  = $results;
        } else {
            $response['error'] = true;
            $response['people'] = array();
            $response['message'] = 'No people found!';
        }

        $db->registerAPICall( $app->username, 'people', 'get', '1');

        echoResponse(200, $response);

        $db = NULL;
    });

// Profiles

$app->get('/users/profile', 'authenticate', function() use($app) {
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getProfileByUsername($app->username);

            $db->registerAPICall( $app->username, 'profile/', 'get', json_encode($result));

            if ($result != NULL) {
                $response['error'] 			= false;
                $response['success']        = true;
                $response['username'] 	    = $result['username'];
			    $response['firstname']      = $result['firstname'];
				$response['lastname']       = $result['lastname'];
				$response['fullname']       = $result['fullname'];
				$response['email']			= $result['email'];
				$response['phone']			= $result['phone'];
				$response['mobilephone']	= $result['mobilephone'];
				$response['resident_type']	= $result['resident_type'];
				$response['unit']			= $result['unit'];
				$response['avatar']         = $_ENV['HTTP_SERVER'].$result['profilepic'];
				$response['privacy']        = $result['privacy'];
                $response['bio']            = $result['bio'];
                $response['twitter']        = $result['twitter'];
                $response['facebook']       = $result['facebook'];
                $response['linkedin']       = $result['linkedin'];

                echoResponse(200, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "The requested resource doesn't exists";
                echoResponse(404, $response);
            }
        });

 $app->put('/users/profile', 'authenticate', function() use($app) {

            $json = $app->request->getBody();
            $data = json_decode($json, true);

            $payload = array(
                        'firstname'     => !empty($data['firstname']) ? ucwords($data['firstname']) : '',
                        'lastname'     => !empty($data['lastname']) ? ucwords($data['lastname']) : '',
                        'email'         => !empty($data['email']) ? strtolower($data['email']) : '',
                        'phone'         => !empty($data['phone']) ? $data['phone'] : '',
                        'mobilephone'   => !empty($data['mobilephone']) ? $data['mobilephone'] : '',
                        'privacy'       => !empty($data['privacy']) ? $data['privacy'] : '',
                );

            $db = new DbHandler();
            $res = $db->updateProfile($app->username, $payload);

 			$db->registerAPICall( $app->username, 'profile', 'put', $res);

            if ($res) {
                $response['error'] 		= false;
                $response['success']    = true;
                $response['username'] 	= $app->username;
                $response['message'] 	= "Profile updated successfully!";
                echoResponse(201, $response);
            } else {
                $response['error'] 		= true;
                $response['username'] 	= $app->username;
                $response['message'] 	= "An error occurred while updating profile. Try again later!";
                echoResponse(400, $response);
            }
        });

  $app->put('/users/password', 'authenticate', function() use($app) {

  			// check for required params
            verifyRequiredParams(array('currentPassword', 'newPassword'));

            // reading post params
        	parse_str($app->request()->getBody(), $request_params);

            $currentPassword 	= $request_params['currentPassword'];
            $newPassword		= $request_params['newPassword'];

            $db = new DbHandler();
            $res = $db->changePassword($app->username, $currentPassword, $newPassword);

 			$db->registerAPICall( $app->username, 'changepassword', 'put', $res);

            if ($res == 'valid') {
                $response['error'] 		= false;
                $response['username'] 	= $app->username;
                $response['message'] 	= "Password changed successfully!";
                echoResponse(201, $response);
            } else if ($res == 'not_password') {
            	$response['error'] 		= true;
                $response['username'] 	= $app->username;
                $response['message'] 	= "Current password entered incorrectly. Please try again!";
                echoResponse(401, $response);
            } else {
                $response['error'] 		= true;
                $response['username'] 	= $app->username;
                $response['message'] 	= "An error occurred while updating password. Try again later!";
                echoResponse(400, $response);
            }


  });

 // Permissions

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

// Announcements / Notifications FROM building management


$app->get('/notifications', 'authenticate', function() use($app) {
            $response = array();

            $db = new DbHandler();

            $page = $app->request()->get('page');

            if (!isset($page) || $page < 1) { $page = 1;}

            $results =  $db->getAllNotifications($app->bid, $page);

            if ($results) {
                $response['success']    = true;
                $response['username'] = $app->username;
                $response['results']  = $results;
            } else {
                $response['error'] = true;
                $response['results'] = array();
                $response['message'] = 'No announcements found!';
            }


			$db->registerAPICall($app->username, 'notifications', 'get', '1');

            echoResponse(200, $response);

            $db = NULL;
        });


$app->get('/notifications/:id', 'authenticate', function($id) use($app) {
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getNotification($app->username, $id);

            $db->registerAPICall($app->username, 'notifications/'.$id, 'get', $result);

            if ($result != NULL) {
                $response['error'] 		= false;
                $response['id'] 		= $result['id'];
                $response['bid'] 		= $result['bid'];
                $response['username'] 	= $result['username'];
                $response['fullname']	= $result['fullname'];
                $response['title']		= $result['title'];
                $response['message']	= $result['message'];
                $response['date_added'] 		= $result['date_added'];
                echoResponse(200, $response);
            } else {
                $response['error'] = true;
                $response['message'] = "The requested notification doesn't exists";
                echoResponse(404, $response);
            }
        });


// list of categories (front desk instructions, maintenance requests, incident reports)

$app->get('/facilities',  'authenticate', function() use($app) {
			$response = array();
            $db = new DbHandler();

            $results = $db->getFacilities($app->bid);

            if ($results) {
                $response['success'] = true;
                $response['facilities'] = $results;
            } else {
                $response['error'] = true;
                $response['message'] = "No facilities found";
            }


			$db->registerAPICall($app->username, 'facilities', 'get', '1');

            echoResponse(200, $response);

            $db = NULL;
        });

$app->get('/resources/:id',  'authenticate', function($id) use($app) {
			$response = array();
            $db = new DbHandler();

            $results = $db->getResources($app->bid, $id);

            if ($results) {
                $response['success'] = true;
                $response['resources'] = $results;
            } else {
                $response['error'] = true;
                $response['message'] = "No facilities found";
            }


			$db->registerAPICall($app->username, 'resources/'.$id, 'get', '1');

            echoResponse(200, $response);

            $db = NULL;
        });

$app->get('/categories/:type',  'authenticate', function($type) use($app) {
			$response = array();
            $db = new DbHandler();

            $results = $db->getCategories($app->username, $type);

            if ($results) {
                $response['success'] = true;
                $response['categories'] = $results;
            } else {
                $response['error'] = true;
                $response['message'] = "No categories for {$type}";
            }


			$db->registerAPICall($app->username, 'categories/'.$type, 'get', '1');

            echoResponse(200, $response);

            $db = NULL;
        });

// autocomplete for mail

$app->get('/autocomplete/:search', 'authenticate', function($search) use($app) {

			$response = array();
            $db = new DbHandler();

            if (isset($search) && $search) {
            	$error = false;
            	$response['error'] 		= false;
            	$response['username'] 	= $app->username;
            	$response['residents'] 	= $db->getResidentAutocomplete($app->username, $search);

				$db->registerAPICall( $app->username, 'autocomplete', 'get', '1');

            	echoResponse(200, $response);

            	$db = NULL;
            } else {
            	$error = true;
            	$response['error'] 		= true;
            	$response['username'] 	= $app->username;
            	$response['residents'] 	= null;
            }

	});

$app->run();

?>
