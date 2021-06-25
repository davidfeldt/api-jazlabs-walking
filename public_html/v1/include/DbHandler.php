<?php

class DbHandler {

  private $conn;

  function __construct() {
      require_once 'DbConnect.php';
      require_once 'Thumbnail.php';
      // opening db connection
      $db = new DbConnect();
      $this->conn = $db->connect();
  }

  public function dateTimeDiff($startDate, $endDate) {
    date_default_timezone_set($_ENV['TIMEZONE']);

    $response = '';

    $dateEnd = date_create($endDate);
    $dateStart= date_create($startDate);

    $diff = date_diff($dateStart, $dateEnd);

    //accessing hours
    $hours=$diff->h;
    //accessing minutes
    $minutes=$diff->i;
    //accessing seconds
    $seconds=$diff->s;

    if ($hours) {
      if ($hours > 1) {
        $response .= $diff->format('%h hours ');
      } else {
        $response .= $diff->format('%h hour ');
      }
    }

    if ($minutes) {
      if ($minutes > 1) {
        $response .= $diff->format('%i mins ');
      } else {
        $response .= $diff->format('%i min ');
      }
    }

    if ($seconds) {
      if ($seconds > 1) {
        $response .= $diff->format('%s secs. ');
      } else {
        $response .= $diff->format('%s sec. ');
      }
    }

    return $response;

  }


  public function startWalk($registrantId) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $now = date('Y-m-d H:i:s');
    $walkId = 0;
    $sql = "INSERT INTO walks SET registrantId = :registrantId, startDate = :startDate, dateAdded = :dateAdded, dateModified = :dateModified";
    $stmt = $this->conn->prepare($sql);
    $stmt->bindParam(':registrantId', $registrantId);
    $stmt->bindParam(':startDate', $now);
    $stmt->bindParam(':dateAdded', $now);
    $stmt->bindParam(':dateModified', $now);

    if ($stmt->execute()) {
      $walkId = $this->conn->lastInsertId();
    }

    return $walkId;
  }

  public function endWalk($registrantId, $walkId) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $now = date('Y-m-d H:i:s');
    $ended = false;
    $sql = "UPDATE walks SET endDate = :endDate, dateModified = :dateModified WHERE registrantId = :registrantId AND walkId = :walkId";
    $stmt = $this->conn->prepare($sql);
    $stmt->bindParam(':registrantId', $registrantId);
    $stmt->bindParam(':walkId', $walkId);
    $stmt->bindParam(':endDate', $now);
    $stmt->bindParam(':dateModified', $now);
    if ($stmt->execute()) {
      $ended = true;
    }

    return $ended;
  }


  public function getFullName($registrantId) {
    $stmt = $this->conn->prepare('SELECT fullName FROM registrants WHERE registrantId = :registrantId');
    $stmt->bindParam(':registrantId', $registrantId);
    if ($stmt->execute()) {
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return !empty($row['fullName']) ? $row['fullName'] : 'N/A';
    } else {
      return '';
    }
  }

  public function getTitle($registrantId) {
    $stmt = $this->conn->prepare('SELECT title FROM registrants WHERE registrantId = :registrantId');
    $stmt->bindParam(':registrantId', $registrantId);
    if ($stmt->execute()) {
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return !empty($row['title']) ? $row['title'] : 'N/A';
    } else {
      return '';
    }
  }

  public function getCompany($registrantId) {
    $stmt = $this->conn->prepare('SELECT company FROM registrants WHERE registrantId = :registrantId');
    $stmt->bindParam(':registrantId', $registrantId);
    if ($stmt->execute()) {
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return !empty($row['company']) ? $row['company'] : 'N/A';
    } else {
      return '';
    }
  }

  private function getEmail($registrantId) {
    $stmt = $this->conn->prepare('SELECT email FROM registrants WHERE registrantId = :registrantId');
    $stmt->bindParam(':registrantId', $registrantId);
    if ($stmt->execute()) {
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return !empty($row['email']) ? $row['email'] : '';
    } else {
      return '';
    }
  }

  private function getMobilephone($registrantId) {
    $stmt = $this->conn->prepare('SELECT mobilephone FROM registrants WHERE registrantId = :registrantId');
    $stmt->bindParam(':registrantId', $registrantId);
    if ($stmt->execute()) {
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return !empty($row['mobilephone']) ? $row['mobilephone'] : '';
    } else {
      return '';
    }
  }


    public function getWalk($registrantId, $walkId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d');
      $response = array ();

      $stmt = $this->conn->prepare("SELECT * FROM walks WHERE walkId = :walkId AND registrantId = :registrantId");
      $stmt->bindParam(':walkId', $walkId);
      $stmt->bindParam(':registrantId', $registrantId);

      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();

        $response  = array (
          'walkId'        => $row['walkId'],
          'registrantId'  => $registrantId,
          'startDate'     => $row['startDate'] ? date('m/d/Y h:i a',strtotime($row['startDate'])) : 'N/A',
          'endDate'       => $row['endDate'] ? date('m/d/Y h:i a',strtotime($row['endDate'])) : 'N/A',
          'duration'      => $row['startDate'] && $row['endDate'] ? $this->dateTimeDiff($row['startDate'], $row['endDate']) : '',
          'locations'     => $this->getLocationsForWalk($row['walkId'], $registrantId),
        );
      }

      return $response;
    }

    public function numberOfWalks($registrantId) {
      $stmt = $this->conn->prepare("SELECT COUNT(*) AS total FROM walks WHERE registrantId >= :registrantId");
      $stmt->bindParam(':registrantId', $registrantId);

      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return (int)$row['total'];
      } else {
        return 0;
      }
    }

    public function getAllWalks($registrantId, $page = 1) {
      $response = array ();

      $limit = $_ENV['LIMIT'];
      $page = (isset($page)) ? $page : 1;
      $start = ($page - 1) * $limit;

      $stmt = $this->conn->prepare("SELECT * FROM walks WHERE registrantId = :registrantId ORDER BY startDate DESC LIMIT $start, $limit");
      $stmt->bindParam(':registrantId', $registrantId);

      if ($stmt->execute()) {
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows AS $row) {

          $response [] = array (
              'walkId'        => $row['walkId'],
              'registrantId'  => $registrantId,
              'startDate'     => $row['startDate'] ? date('m/d/Y h:i a',strtotime($row['startDate'])) : 'N/A',
              'endDate'       => $row['endDate'] ? date('m/d/Y h:i a',strtotime($row['endDate'])) : 'N/A',
              'duration'      => $row['startDate'] && $row['endDate'] ? $this->dateTimeDiff($row['startDate'], $row['endDate']) : '',
              'locations'     => $this->getLocationsForWalk($row['walkId'], $registrantId),
            );
        }
      }

      return $response;

    }



    private function getMessagingChannelFor($registrantId) {
      $stmt = $this->conn->prepare('SELECT messaging FROM registrants WHERE registrantId = :registrantId');
      $stmt->bindParam(':registrantId', $registrantId);
      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return !empty($row['messaging']) ? $row['messaging'] : 'none';
      } else {
        return 'none';
      }
    }


    private function sendEmailToAdmin($adminId, $subject, $message) {
      $to_name = $this->getAdminFullName($adminId);
      $to_email = $this->getAdminEmail($adminId);

      if (!empty($to_name) && !empty($to_email)) {
        $email = new \SendGrid\Mail\Mail();
        $email->setFrom($_ENV['SENDGRID_FROM_EMAIL'], $_ENV['SENDGRID_FROM_NAME']);
        $email->setSubject($subject);
        $email->addTo($to_email, $to_name);
        $email->setTemplateId($_ENV['NOTIFICATION_TEMPLATE_ID']);
        $email->addDynamicTemplateData("subject", $subject);
        $email->addDynamicTemplateData("message", nl2br($message));
        $sendgrid = new \SendGrid(getenv('SENDGRID_API_KEY'));
        try {
            $response = $sendgrid->send($email);
            return $response;
        } catch (Exception $e) {
            return 'Caught exception: '. $e->getMessage() ."\n";
        }
      }
    }

    private function sendEmailNotification($registrantId, $subject, $message, $rowId = 0) {
      $to_name = $this->getFullName($registrantId);
      $to_email = $this->getEmail($registrantId);

      if (!empty($to_name) && !empty($to_email)) {
        $email = new \SendGrid\Mail\Mail();
        $email->setFrom($_ENV['SENDGRID_FROM_EMAIL'], $_ENV['SENDGRID_FROM_NAME']);
        $email->setSubject($subject);
        $email->addTo($to_email, $to_name);
        $email->setTemplateId($_ENV['NOTIFICATION_TEMPLATE_ID']);
        $email->addDynamicTemplateData("subject", $subject);
        if ($rowId) {
          $row = $this->getEvent($registrantId, $rowId);
          $email->addDynamicTemplateData("event", $row);
        }
        if ($message) {
          $email->addDynamicTemplateData("message", nl2br($message));
        }
        $sendgrid = new \SendGrid(getenv('SENDGRID_API_KEY'));
        try {
            $response = $sendgrid->send($email);
            return $response;
        } catch (Exception $e) {
            return 'Caught exception: '. $e->getMessage() ."\n";
        }
      }
    }

    private function sendSMSNotification($registrantId, $message) {
      $mobilephone = $this->getMobilephone($registrantId);
      return $this->sendSMS($mobilephone, $message);
    }

    public function sendNotification($registrantId, $subject = '', $message = '', $rowId = 0) {
      $messaging = $this->getMessagingChannelFor($registrantId);
      switch ($messaging) {
        case 'email':
          $result = $this->sendEmailNotification($registrantId, $subject, $message, $rowId);
          break;
        case 'sms':
          $result = $this->sendSMSNotification($registrantId, $subject);
          break;
        case 'push':
          $result = $this->sendPushNotificationsToIndividual($registrantId, $subject);
          break;
        case 'none':
          $result = false;
          break;
        default:
          $result = false;
          break;
      }

      return $result;
    }


	public function forgotPassword($username) {
    date_default_timezone_set($_ENV['TIMEZONE']);
      	$stmt = $this->conn->prepare('SELECT username, registrantId, email, mobilephone FROM registrants WHERE username = :username');

        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();

        if (isset($row) && $row) {
          	// Found registrant with the username
          	// Generate new reset code
          	$email		         = $row['email'];
          	$mobilephone       = $row['mobilephone'];
            $registrantId      = $row['registrantId'];

            $reset_code_short  = mt_rand(100000,999999);
            $reset_code = sha1(uniqid(rand(), true));
            date_default_timezone_set($_ENV['TIMEZONE']);
            $reset_dt = date('Y-m-d H:i:s');
            $reset_code_active = 1;

            $stmt = $this->conn->prepare('UPDATE registrants SET reset_code = :reset_code, reset_code_short = :reset_code_short, reset_code_active = :reset_code_active, reset_dt = :reset_dt, dateModified = NOW() WHERE username = :username');
            $stmt->bindParam(':username',$username);
            $stmt->bindParam(':reset_code',$reset_code);
            $stmt->bindParam(':reset_code_short',$reset_code_short);
            $stmt->bindParam(':reset_code_active',$reset_code_active);
            $stmt->bindParam(':reset_dt',$reset_dt);
            $stmt->execute();

            $from_name 	= $this->getSetting('config_name');
            $from_url	= $_ENV['HTTP_CATALOG'];
	     	    $subject 	= 'Password Reset';
	     	    $message 	= '<p>Someone just requested that the password be reset for your account at '.$from_name.'.</p><p>If this was a mistake, just ignore this email and nothing will happen.</p><p>To reset your password, enter the following code on your phone when prompted:</p>
	   <p>'.$reset_code.'</p>';

            if ($mobilephone) {
              $this->sendSMS($mobilephone, 'Reset code is: '.$reset_code_short);
              return 'mobile';
            } else if ($email) {
              $this->sendEmailNotification($username, $email, $subject, $message);
              return 'email';
            } else {
              return false;
            }

        } else {
            // registrant not existed with the email
            return 'not_username';
        }
   }


   private function getUsernameFromResetCode($reset_code) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $sql = "SELECT username FROM registrants WHERE (reset_code = :reset_code OR reset_code_short = :reset_code) AND reset_code_active = '1' AND reset_dt >= DATE_SUB(NOW(), INTERVAL 30 MINUTE)";
    $stmt = $this->conn->prepare($sql);

    $stmt->bindParam(':reset_code', $reset_code);
    if ($stmt->execute()) {
      $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return $row['username'];
    } else {
      return false;
    }

   }


  private function isCodeValid($reset_code_short, $username) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $now = date('Y-m-d H:i:s');

    $sql = "SELECT COUNT(*) AS total FROM registrants WHERE username = :username AND reset_code_short = :reset_code_short AND reset_code_active = '1' AND reset_dt >= DATE_SUB(:now, INTERVAL 30 MINUTE)";
    $stmt = $this->conn->prepare($sql);
    $stmt->bindParam(':username', $username);
    $stmt->bindParam(':reset_code_short', $reset_code_short);
    $stmt->bindParam(':now', $now);

    if ($stmt->execute()) {
      $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return $row['total'] > 0;
    } else {
      return false;
    }
  }

  public function isUserVerified($registrantId) {
    $sql = "SELECT COUNT(*) AS total FROM registrants WHERE registrantId = :registrantId AND verified = '1'";
    $stmt = $this->conn->prepare($sql);
    $stmt->bindParam(':registrantId', $registrantId);

    if ($stmt->execute()) {
      $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return $row['total'] > 0;
    } else {
      return false;
    }
  }

  public function verifyAccount($verifyCode, $username) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    if ($this->isCodeValid($verifyCode, $username)) {
      $stmt = $this->conn->prepare("UPDATE registrants SET verified = '1', reset_code = '', reset_code_short = '', reset_code_active = '0', dateModified = NOW() WHERE username = :username and reset_code_short = :reset_code_short");
      $stmt->bindParam(':reset_code_short', $verifyCode);
      $stmt->bindParam(':username', $username);
      if ($stmt->execute()) {
        $user = $this->getProfileByUsername($username);
        $this->addActivity($user['registrantId'], 'login', ' logged into app.');
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  public function resetPassword($reset_code, $password) {
    date_default_timezone_set($_ENV['TIMEZONE']);

    $username = $this->getUsernameFromResetCode($reset_code);

    if ($username) {
      $password_hash = password_hash($password, PASSWORD_DEFAULT);

      $stmt = $this->conn->prepare("UPDATE registrants SET password = :password, reset_code = '', reset_code_short = '', verified = '1', reset_code_active = '0', dateModified = NOW() WHERE username = :username");
      $stmt->bindParam(':username', $username);
      $stmt->bindParam(':password', $password_hash);
      if ($stmt->execute()) {
        return true;
      } else {
        return false;
      }

    } else {
      return false;

    }

  }

  public function sendSMS($number, $message) {

		// Your Account SID and Auth Token from twilio.com/console
		$sid = $_ENV['TWILIO_SID'];
		$token = $_ENV['TWILIO_TOKEN'];
		$fromNumber = $_ENV['TWILIO_NUMBER'];

    $client = new Twilio\Rest\Client($sid, $token);

		$toNumber = trim($number," ()-");

		if (strlen($toNumber) === 10) {
			$toNumber = '+1'.$toNumber;
		}

		$client->messages->create(
		    $toNumber,
		    array(
		        'from' => $fromNumber,
		        'body' => $message
		    )
		);

    return array(
      'from'    => $fromNumber,
      'to'      => $toNumber,
      'message' => $message
    );
	}



  public function changePassword($username, $current_password, $new_password) {
    $response = array();

   	  if ($this->checkLogin($username,$current_password) != 'valid') {
   	  	return 'not_password';
   	  } else {

        // Generating password hash
        $password_hash = password_hash($new_password, PASSWORD_DEFAULT);

        // Generating new API key
        //$api_key = $this->generateApiKey();


        // insert query
        $stmt = $this->conn->prepare('UPDATE registrants SET password = :password WHERE username = :username');
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':password',$password_hash);
        //$stmt->bindParam(':apiKey',$api_key);

        $result = $stmt->execute();

        // Check for successful insertion
        if ($result) {
            // User successfully inserted
            return 'valid';
        } else {
            // Failed to create user
            return 'not_done';
        }
    }
  }


  public function checkUsername($username) {
    $stmt = $this->conn->prepare("SELECT COUNT(username) AS total FROM registrants WHERE username = :username");

    $stmt->bindParam(':username', $username);
    $stmt->execute();
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
    $row = $stmt->fetch();

    if (isset($row) && $row) {
        // Found registrant with the username
        // Now verify the password

        if ($row['total'] == 1) {
            // Username exists and is correct
            return 'valid';
        } else {
            // Username not valid
            return 'not_valid';
        }
    } else {
        // No username found
        return 'not_valid';
    }
  }


  public function formatPhoneNumber($sPhone){
  	if (empty($sPhone)) return "";

  	$sPhone = trim($sPhone,' ()-+');
  	if(strlen($sPhone) != 10) return "Error";

  	$sArea = substr($sPhone,0,3);
  	$sPrefix = substr($sPhone,3,3);
  	$sNumber = substr($sPhone,6,4);
  	$sPhone = "(".$sArea.") ".$sPrefix."-".$sNumber;
  	return($sPhone);
  }


  private function addActivity($registrantId, $code = '', $comment) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $now = date('Y-m-d H:i:s');
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $sql = "INSERT INTO activity_log SET registrantId = :registrantId, code = :code, comment = :comment, dateAdded = :dateAdded, ipAddress = :ipAddress";
    $stmt = $this->conn->prepare($sql);
    $stmt->bindParam(':registrantId', $registrantId);
    $stmt->bindParam(':code', $code);
    $stmt->bindParam(':comment', $comment);
    $stmt->bindParam(':dateAdded', $now);
    $stmt->bindParam(':ipAddress', $ipAddress);
    if ($stmt->execute()) {
      return true;
    } else {
      return false;
    }
  }


  private function generateUniqueUsername($username){
    $new_username   = strtolower($username);
    $count = $this->howManyUsernamesLike($new_username);

    if(!empty($count)) {
        $new_username = $new_username . $count;
    }

    return $new_username;
  }


  public function addUser($data) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $now = date('Y-m-d H:i:s');
    $response = array();

    $firstName = !empty($data['firstName']) ? ucwords($data['firstName']) : '';
		$lastName = !empty($data['lastName']) ? ucwords($data['lastName']) : '';
    $fullName = ucwords($firstName)." ".ucwords($lastName);
    $title = !empty($data['title']) ? ucwords(trim($data['title'])) : '';
		$company = !empty($data['company']) ? ucwords(trim($data['company'])) : '';
		$email = !empty($data['email']) ? strtolower(trim($data['email'])) : '';
		$mobilephone = !empty($data['mobilephone']) ? $data['mobilephone'] : '';
		$username = !empty($data['username']) ? $data['username'] : '';
    $username = $this->generateUniqueUsername($username);

    $stmt = $this->conn->prepare("INSERT INTO registrants SET
            firstName = :firstName,
            lastName = :lastName,
            fullName = :fullName,
            email = :email,
            phone = '',
            profileVisible = '0',
            messaging = 'email',
            pushNotifications = '0',
            mobilephone = :mobilephone,
            title = :title,
            company = :company,
            dateAdded = :now,
            dateModified = :now,
            username = :username");
    $stmt->bindParam(':firstName', $firstName);
    $stmt->bindParam(':lastName', $lastName);
    $stmt->bindParam(':fullName', $fullName);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':mobilephone', $mobilephone);
    $stmt->bindParam(':title', $title);
    $stmt->bindParam(':company', $company);
    $stmt->bindParam(':now', $now);
    $stmt->bindParam(':username', $username);
    if ($stmt->execute()) {
      $response['success'] = true;
      $response['username'] = $username;
      $response['message'] = ' You have registered successfully!';

    } else {
      $response['success'] = false;
      $response['error'] = true;
      $response['message'] = 'There was an error adding your account. Try again later!';
    }

    return $response;
  }

  public function sendVerificationCode($username) {
    // create verification code and send to user
    $profile = $this->getProfileByUsername($username);

    if (!empty($profile)) {
      $reset_code_short  = mt_rand(100000,999999);
      $reset_code = sha1(uniqid(rand(), true));
      date_default_timezone_set($_ENV['TIMEZONE']);
      $reset_dt = date('Y-m-d H:i:s');
      $reset_code_active = 1;

      $mobilephone = $this->getMobilephone($profile['registrantId']);
      $registrantId = $profile['registrantId'];

      $stmt = $this->conn->prepare('UPDATE registrants SET reset_code = :reset_code, reset_code_short = :reset_code_short, reset_code_active = :reset_code_active, reset_dt = :reset_dt, dateModified = NOW() WHERE registrantId = :registrantId');
      $stmt->bindParam(':registrantId', $registrantId);
      $stmt->bindParam(':reset_code',$reset_code);
      $stmt->bindParam(':reset_code_short',$reset_code_short);
      $stmt->bindParam(':reset_code_active',$reset_code_active);
      $stmt->bindParam(':reset_dt',$reset_dt);
      if ($stmt->execute()) {
        $response['success'] = true;
        $response['error'] = false;
        $subject 	= 'Verification Code';
        $message 	= '<p>To log into your account, please enter the following verification code on your phone: <strong>'.$reset_code.'</strong></p>';

        if ($mobilephone) {
          $this->sendSMSNotification($registrantId, 'Verification code is: '.$reset_code_short);
          $response['message'] = 'Please enter the verification code we just sent to log into your account.';
          $response['channel'] = 'mobile';
        } else if ($email) {
          $this->sendEmailNotification($registrantId, $subject, $message);
          $response['message'] = 'Please enter the verification code (sent to your email) on your phone to log into your account.';
          $response['channel'] = 'email';
        }
      } else {
        $response['success'] = false;
        $response['error'] = true;
        $response['message'] = 'There was an error sending your verification code. Try again later!';
      }
    } else {
      $response['success'] = false;
      $response['error'] = true;
      $response['message'] = 'No profile found for your username!';
    }

    return $response;
  }


  public function getProfileByUsername($username) {
      $stmt = $this->conn->prepare('SELECT registrantId, username, firstName, lastName, fullName, email, phone, mobilephone, title, company, profileVisible, messaging, pushNotifications, verified FROM registrants WHERE username = :username');
      $stmt->bindParam(':username', $username);
      if ($stmt->execute()) {
      	$stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return $row;
      } else {
          return NULL;
      }
  }


  public function updateProfile($username, $data) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $profile = $this->getProfileByUsername($username);

    if (!empty($data['firstName']) && !empty($data['lastName'])) {
      $firstName = ucwords(trim($data['firstName']));
      $lastName = ucwords(trim($data['lastName']));
      $fullName = $firstName." ".$lastName;

      $stmt = $this->conn->prepare('UPDATE registrants SET firstName = :firstName, lastName = :lastName, fullName = :fullName, dateModified=NOW()  WHERE username = :username');
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':firstName',$firstName);
      $stmt->bindParam(':lastName',$lastName);
      $stmt->bindParam(':fullName',$fullName);
      $stmt->execute();

    }

    if (!empty($data['email'])) {
      $email = strtolower($data['email']);
      $stmt = $this->conn->prepare('UPDATE registrants SET email = :email, dateModified=NOW() WHERE username = :username');
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':email',$email);
      $stmt->execute();
    }

    if (!empty($data['phone'])) {
      $stmt = $this->conn->prepare('UPDATE registrants SET phone = :phone, dateModified=NOW() WHERE username = :username');
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':phone',$data['phone']);
      $stmt->execute();
    }

    if (!empty($data['mobilephone'])) {
      $stmt = $this->conn->prepare('UPDATE registrants SET mobilephone = :mobilephone, dateModified=NOW() WHERE username = :username');
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':mobilephone',$data['mobilephone']);
      $stmt->execute();
    }

    if (!empty($data['title'])) {
      $title = ucwords(trim($data['title']));
      $stmt = $this->conn->prepare('UPDATE registrants SET title = :title, dateModified=NOW() WHERE username = :username');
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':title',$title);
      $stmt->execute();
    }

    if (!empty($data['company'])) {
      $company = ucwords(trim($data['company']));
      $stmt = $this->conn->prepare('UPDATE registrants SET company = :company, dateModified=NOW() WHERE username = :username');
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':company',$company);
      $stmt->execute();
    }

    if (isset($data['profileVisible'])) {
      $stmt = $this->conn->prepare('UPDATE registrants SET profileVisible = :profileVisible, dateModified=NOW() WHERE username = :username');
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':profileVisible',$data['profileVisible']);
      $stmt->execute();
    }

    if (isset($data['pushNotifications'])) {
      if ($data['pushNotifications'] == '0') {
        if ($profile['messaging'] == 'push') {
          // force messaging to be none if messaging is push and use set pushNotifications = 0
          $stmt = $this->conn->prepare("UPDATE registrants SET pushNotifications = :pushNotifications, messaging = 'none', dateModified=NOW() WHERE username = :username");
          $stmt->bindParam(':username',$username);
          $stmt->bindParam(':pushNotifications',$data['pushNotifications']);
          $stmt->execute();
        } else {
          $stmt = $this->conn->prepare("UPDATE registrants SET pushNotifications = :pushNotifications, dateModified=NOW() WHERE username = :username");
          $stmt->bindParam(':username',$username);
          $stmt->bindParam(':pushNotifications',$data['pushNotifications']);
          $stmt->execute();
        }
      } else {
        $stmt = $this->conn->prepare('UPDATE registrants SET pushNotifications = :pushNotifications, dateModified=NOW() WHERE username = :username');
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':pushNotifications',$data['pushNotifications']);
        $stmt->execute();
      }
    }

    if (!empty($data['messaging'])) {
      if ($data['messaging'] == 'push') {
        // force pushNotifications to be '1' if user wants to receive messaging via push notification
        $stmt = $this->conn->prepare("UPDATE registrants SET messaging = :messaging, pushNotifications = '1', dateModified=NOW() WHERE username = :username");
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':messaging',$data['messaging']);
        $stmt->execute();
      } else {
        $stmt = $this->conn->prepare("UPDATE registrants SET messaging = :messaging, dateModified=NOW() WHERE username = :username");
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':messaging',$data['messaging']);
        $stmt->execute();
      }
    }



    return true;
  }


  private function howManyUsernamesLike($username) {
    $username = "%".$username."%";
    $sql = "SELECT COUNT(*) AS total FROM registrants WHERE username LIKE :username";
    $stmt     = $this->conn->prepare($sql);
    $stmt->bindParam(':username', $username);

    if ($stmt->execute()) {
      $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return $row['total'];
    } else {
      return '';
    }
  }

  private function chooseColor() {
    $sql = "SELECT * FROM colors";
    $stmt = $this->conn->prepare($sql);
    $stmt->execute();
    $colors = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $random = array_rand($colors);
    return $colors[$random];
  }

  public function getCalendarMarkedDates($startDate, $endDate)  {
    $dates_data  = array();
    date_default_timezone_set($_ENV['TIMEZONE']);
    $startDate = date('Y-m-d', strtotime($startDate));
    $endDate = date('Y-m-d', strtotime($endDate));
    $today = date('Y-m-d');

    $stmt = $this->conn->prepare("SELECT startDate, endDate FROM walks WHERE DATE(startDate) >= :startDate AND DATE(endDate) <= :endDate ORDER BY startDate ASC");
    $stmt->bindParam(':startDate', $startDate);
    $stmt->bindParam(':endDate', $endDate);

    if ($stmt->execute()) {
      $dates = $stmt->fetchAll(PDO::FETCH_ASSOC);

      if ($dates) {
        foreach ($dates AS $date) {
            $start_date = date('Y-m-d', strtotime($date['startDate']));
            $end_date = date('Y-m-d', strtotime($date['endDate']));
            $colorPair = $this->chooseColor();
            $color = $colorPair['color'];
            if ($start_date == $end_date) {
              $dates_data[$start_date] = array(
                'color'       => $color,
                'textColor'   => 'white',
                'selected'    => $today == $start_date,
                'startingDay' => true,
                'endingDay'   => true,
              );
            } else {
              $dates_data[$start_date] = array (
                'startingDay'  => true,
                'selected'     => $today == $start_date,
                'color'        => $color,
                'textColor' => 'white'
              );
              $day_after_start_date = date ("Y-m-d", strtotime("+1 days", strtotime($start_date)));
              $day_before_end_date = date ("Y-m-d", strtotime("-1 days", strtotime($end_date)));
              while (strtotime($day_after_start_date) <= strtotime($day_before_end_date)) {
                $dates_data[$day_after_start_date] = array (
                  'color'     => $color,
                  'textColor' => 'white'
                );
                $day_after_start_date = date ("Y-m-d", strtotime("+1 days", strtotime($day_after_start_date)));
              }
              $dates_data[$end_date] = array (
                'selected'  => $today == $end_date,
                'endingDay' => true,
                'color'     => $color,
                'textColor' => 'white'
              );
            }
        }
      }
    }
    return $dates_data;
  }


    private function guidv4($data = null) {
      $data = $data ?? random_bytes(16);

      $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
      $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

      return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }


    public function getWalksForCalendar($registrantId, $day) {
   		date_default_timezone_set($_ENV['TIMEZONE']);
      $day = date('Y-m-d', strtotime($day));
   		$rowData = array();
   		$stmt = $this->conn->prepare("SELECT * FROM walks WHERE DATE(startDate) <= :day AND DATE(endDate) >= :day AND registrantId = :registrantId ORDER BY startDate ASC");
  		$stmt->bindParam(':day', $day);
  		$stmt->bindParam(':registrantId', $registrantId);
  		if ($stmt->execute()) {
  			$walks = $stmt->fetchAll(PDO::FETCH_ASSOC);
  			foreach ($walks AS $row) {
  				$times = $row['startDate'] == $row['endDate'] ? date('m/d',strtotime($row['startDate'])) : date('m/d',strtotime($row['startDate']))." - ".date('m/d',strtotime($row['endDate']));
  				$rowData[] = array (
  					'times'		      => $times,
  					'height'	      => 50,
            'walkId'        => $row['walkId'],
            'registrantId'  => $registrantId,
            'startDate'     => date('m/d/Y',strtotime($row['startDate'])),
            'endDate'       => date('m/d/Y',strtotime($row['endDate'])),
            'locations'     => $this->getLocationsForWalk($row['walkId'], $registrantId),
  				);

  			}
  		}

  		return $rowData;
   	}

		public function sendPushNotificationsToIndividual($registrantId, $message, $data = array(), $sound = 0) {

			// get group members
			$filters = array(
  				array(
  				"field"     => "tag",
  				"key"       => "registrantId",
  				"relation"  => "=",
  				"value"     => (int)$registrantId
  			)
			);

			// create push notification data
			$contents = array(
				"en" => $message,
			);

			$fields = array(
				'app_id'    => $_ENV['ONESIGNAL_APP_ID'],
				'contents'    => $contents,
				// 'data'    => $data,
				'filters'   => $filters,
				// 'ios_sound' => $sound ? 'alert.wav' : ''
			);

			$fields = json_encode($fields);
				$ch = curl_init();
				curl_setopt($ch, CURLOPT_URL, $_ENV['ONESIGNAL_API_URL']);
				curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json; charset=utf-8',
														 'Authorization: Basic '.$_ENV['ONESIGNAL_API_KEY']));
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
				curl_setopt($ch, CURLOPT_HEADER, FALSE);
				curl_setopt($ch, CURLOPT_POST, TRUE);
				curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
				curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);

				$response = curl_exec($ch);
				curl_close($ch);

			return json_decode($response, true);
		}


}

?>
