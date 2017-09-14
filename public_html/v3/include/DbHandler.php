<?php

// These constants may be changed without breaking existing hashes.
	define("PBKDF2_HASH_ALGORITHM", "sha256");
	define("PBKDF2_ITERATIONS", 50000);
	define("PBKDF2_SALT_BYTE_SIZE", 24);
	define("PBKDF2_HASH_BYTE_SIZE", 24);

	define("HASH_SECTIONS", 4);
	define("HASH_ALGORITHM_INDEX", 0);
	define("HASH_ITERATION_INDEX", 1);
	define("HASH_SALT_INDEX", 2);
	define("HASH_PBKDF2_INDEX", 3);
 
class DbHandler {
 
    private $conn;
 
    function __construct() {
        require_once 'DbConnect.php';
        require_once 'Thumbnail.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }
    
    public function create_hash($password) {
    	// format: algorithm:iterations:salt:hash
		$salt = base64_encode(mcrypt_create_iv(PBKDF2_SALT_BYTE_SIZE, MCRYPT_DEV_URANDOM));
		return PBKDF2_HASH_ALGORITHM . ":" . PBKDF2_ITERATIONS . ":" .  $salt . ":" . 
        	base64_encode($this->pbkdf2(
            	PBKDF2_HASH_ALGORITHM,
				$password,
				$salt,
				PBKDF2_ITERATIONS,
				PBKDF2_HASH_BYTE_SIZE,
				true
			));
	}
	
	public function validate_password($password, $correct_hash) {
    	$params = explode(":", $correct_hash);
		if(count($params) < HASH_SECTIONS)
			return false; 
		$pbkdf2 = base64_decode($params[HASH_PBKDF2_INDEX]);
		return $this->slow_equals(
        		$pbkdf2,
				$this->pbkdf2(
				$params[HASH_ALGORITHM_INDEX],
				$password,
				$params[HASH_SALT_INDEX],
				(int)$params[HASH_ITERATION_INDEX],
				strlen($pbkdf2),
				true
				));
	}

	// Compares two strings $a and $b in length-constant time.
	private function slow_equals($a, $b) {
    	$diff = strlen($a) ^ strlen($b);
		for($i = 0; $i < strlen($a) && $i < strlen($b); $i++) {
        	$diff |= ord($a[$i]) ^ ord($b[$i]);
		}
		return $diff === 0; 
	}

	/*
	 * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     * $algorithm - The hash algorithm to use. Recommended: SHA256
     * $password - The password.
     * $salt - A salt that is unique to the password.
     * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
     * $key_length - The length of the derived key in bytes.
     * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
     * Returns: A $key_length-byte key derived FROM the password and salt.
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by https://defuse.ca
     * With improvements by http://www.variations-of-shadow.com
     */

	 private function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false) {
		 $algorithm = strtolower($algorithm);
		 if(!in_array($algorithm, hash_algos(), true))
		 	trigger_error('PBKDF2 ERROR: Invalid hash algorithm.', E_USER_ERROR);
		 if($count <= 0 || $key_length <= 0)
		 	trigger_error('PBKDF2 ERROR: Invalid parameters.', E_USER_ERROR);

		 if (function_exists("hash_pbkdf2")) {
			 // The output length is in NIBBLES (4-bits) if $raw_output is false!
			 if (!$raw_output) {
				 $key_length = $key_length * 2;
			 }
			 return hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output);
		 }

		 $hash_length = strlen(hash($algorithm, "", true));
		 $block_count = ceil($key_length / $hash_length);

		 $output = "";
		 for($i = 1; $i <= $block_count; $i++) {
			 // $i encoded as 4 bytes, big endian.
			 $last = $salt . pack("N", $i);
			 // first iteration
			 $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
			 // perform the other $count - 1 iterations
			 for ($j = 1; $j < $count; $j++) {
				 $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
			 }
			 $output .= $xorsum;
		 }

		 if($raw_output)
		 	return substr($output, 0, $key_length);
		 else
		 	return bin2hex(substr($output, 0, $key_length));
	 }

   public function captureDebug($endpoint, $request, $response) {
    date_default_timezone_set("America/Toronto");
    $date_added  = date('Y-m-d H:i:s');
    $ip          = $_SERVER['REMOTE_ADDR'];
    
    $stmt = $this->conn->prepare("INSERT INTO debug SET endpoint = :endpoint, request = :request, response = :response, date_added = :date_added, ip = :ip");
      $stmt->bindParam(':endpoint',$username);
      $stmt->bindParam(':request',$endpoint);
      $stmt->bindParam(':response',$status);
      $stmt->bindParam(':ip',$ip);
      $stmt->bindParam(':date_added',$dt);
      
      $result = $stmt->execute();
      
      if ($result) {
        return TRUE;
      } else {
        return NULL;
      }
   
   }
	 
	 public function registerAPICall($username, $endpoint, $type, $status) {
	 	date_default_timezone_set("America/Toronto");
	 	$date_added  = date('Y-m-d H:i:s');
	 	$ip          = $_SERVER['REMOTE_ADDR'];
	 	$profile 		 = $this->getProfileByUsername($username);
    $bid			   = $profile['bid'];
	 	
	 	$stmt = $this->conn->prepare('INSERT INTO apiCalls SET username = :username, date_added = :date_added, ip = :ip, bid = :bid, endpoint = :endpoint, type = :type, status = :status');
    	$stmt->bindParam(':username',$username);
    	$stmt->bindParam(':endpoint',$endpoint);
    	$stmt->bindParam(':status',$status);
    	$stmt->bindParam(':type',$type);
    	$stmt->bindParam(':ip',$ip);
    	$stmt->bindParam(':date_added',$dt);
    	$stmt->bindParam(':bid',$bid);
    	
    	$result = $stmt->execute();
    	
    	if ($result) {
    		return TRUE;
    	} else {
    		return NULL;
    	}
	 
	 }
	
	private function dateDiff($start, $end) {
  		$start_ts = strtotime($start);
  		$end_ts = strtotime($end);
  		$diff = $end_ts - $start_ts;
  		return round($diff / 86400);
	}
	
  public function dateTimeDiff($dt) {
    date_default_timezone_set('America/Toronto');
    $now = date('Y-m-d H:i:s');

    $dateNow = date_create($now);
    $dateThen= date_create($dt);

    $diff = date_diff($dateThen, $dateNow);

    //accessing days
    $days = $diff->d;
    //accessing months
    $months = $diff->m;
    //accessing years
    $years = $diff->y;
    //accessing hours
    $hours=$diff->h;
    //accessing minutes
    $minutes=$diff->i;
    //accessing seconds
    $seconds=$diff->s;

    if ($months) {
      return date('m/d/Y',strtotime($dt));
    } elseif ($days) {
      if ($days > 7) {
        return date('m/d/Y',strtotime($dt));
      } elseif ($days > 1) {
        return $diff->format('%d days %h hours ago');
      } else {
        return $diff->format('%d day %h hours ago');
      }
    } elseif ($hours) {
      if ($hours > 1) {
        return $diff->format('%h hours %i mins ago');
      } else {
        return $diff->format('%h hour %i mins ago');
      }
    } elseif ($minutes) {
      if ($minutes > 1) {
        return $diff->format('%i mins ago');
      } else {
        return $diff->format('%i min ago');
      }
    } else {
      return $diff->format('%s secs ago');
    }

  }

		 
	 private function uploadMaintenanceImage(){
		$upload_dir = $_ENV['DIR_MAINTENANCEREPORT'];   

		$size_bytes = 10194304; // File Size in bytes 

		$extlimit = "yes"; //Do you want to limit the extensions of files uploaded (yes/no)
		$limitedext = array(".jpg",".png",".jpeg",".JPG", ".PNG", ".gif", ".GIF"); //Extensions you want files uploaded limited to.

          //check if the directory exists or not.
          if (!is_dir("$upload_dir")) {
	     	die ("The directory $upload_dir doesn't exist");
          }
          //check if the directory is writable.
          if (!is_writeable("$upload_dir")){
             die ("The directory $upload_dir is NOT writable, Please CHMOD (777)");
          }

              //check if no file selected.
              if (!is_uploaded_file($_FILES['fileUpload']['tmp_name']))
                     return "no file";

              //Get the Size of the File
              $size = $_FILES['fileUpload']['size'];
              //Make sure that file size is correct
              //if ($size > $size_bytes)
              //{
              //      $kb = $size_bytes / 1024000;
              //      echo "The file you are trying to upload is too large. The file must be <b>$Mb</b> KB or less.";
              //      exit();
              //}

              //check file extension
			  $extCheck = $ext;
              $extCheck = strrchr($_FILES['fileUpload']['name'],'.');
              if (($extlimit == "yes") && (!in_array($extCheck,$limitedext))) {
                    echo("This file type is not supported. Please only upload .jpg, .jpeg, or .png files.");
                    exit();
              }

              // $filename will hold the value of the file name submitted FROM the form.
              $filename =  date(YmdHis)."_".$_FILES['fileUpload']['name'];
              // Check if file is Already EXISTS.
              if(file_exists($upload_dir.$filename)){
                    echo "Oops! The file named $filename already exists.";
                    exit();
              }

              //Move the File to the Directory of your choice
              //move_uploaded_file('filename','destination') Moves afile to a new location.
              if (move_uploaded_file($_FILES['fileUpload']['tmp_name'],$upload_dir.$filename)) {
						chmod($upload_dir.$filename, 0604);
                  //tell the user that the file has been uploaded and make him alink.

						return $_ENV['PATH_MAINTENANCEREPORT'].$filename;
						
                  //exit();

              }
                  // print error if there was a problem moving file.
                  else
              {
                  //Print error msg.
                  $msg = "There+was+a+problem+moving+your+file.+Please+try+later.";
                  return $msg;
              }
	}
	
	private function uploadIncidentImage(){
		$upload_dir = $_ENV['DIR_INCIDENTREPORT'];   

		$size_bytes = 10194304; // File Size in bytes 

		$extlimit = "yes"; //Do you want to limit the extensions of files uploaded (yes/no)
		$limitedext = array(".jpg",".png",".jpeg",".JPG",".JPEG",".PNG", ".gif", ".GIF"); //Extensions you want files uploaded limited to.

          //check if the directory exists or not.
          if (!is_dir("$upload_dir")) {
	     	die ("The directory $upload_dir doesn't exist");
          }
          //check if the directory is writable.
          if (!is_writeable("$upload_dir")){
             die ("The directory $upload_dir is NOT writable, Please CHMOD (777)");
          }

              //check if no file selected.
              if (!is_uploaded_file($_FILES['fileUpload']['tmp_name']))
                     return "no file";

              //Get the Size of the File
              $size = $_FILES['fileUpload']['size'];
              //Make sure that file size is correct
              //if ($size > $size_bytes)
              //{
              //      $kb = $size_bytes / 1024000;
              //      echo "The file you are trying to upload is too large. The file must be <b>$Mb</b> KB or less.";
              //      exit();
              //}

              //check file extension
			  $extCheck = $ext;
              $extCheck = strrchr($_FILES['fileUpload']['name'],'.');
              if (($extlimit == "yes") && (!in_array($extCheck,$limitedext))) {
                    echo("This file type is not supported. Please only upload .jpg, .jpeg, or .png files.");
                    exit();
              }

              // $filename will hold the value of the file name submitted FROM the form.
              $filename =  date(YmdHis)."_".$_FILES['fileUpload']['name'];
              // Check if file is Already EXISTS.
              if(file_exists($upload_dir.$filename)){
                    echo "Oops! The file named $filename already exists.";
                    exit();
              }

              //Move the File to the Directory of your choice
              //move_uploaded_file('filename','destination') Moves afile to a new location.
              if (move_uploaded_file($_FILES['fileUpload']['tmp_name'],$upload_dir.$filename)) {
						chmod($upload_dir.$filename, 0604);
                  //tell the user that the file has been uploaded and make him alink.

						return $_ENV['PATH_INCIDENTREPORT'].$filename;
						
                  //exit();

              }
                  // print error if there was a problem moving file.
                  else
              {
                  //Print error msg.
                  $msg = "There+was+a+problem+moving+your+file.+Please+try+later.";
                  return $msg;
              }
	}
	
	private function uploadWallImages(){
		$upload_dir = $_ENV['DIR_WALLPOST'];   
		$extlimit = "yes"; //Do you want to limit the extensions of files uploaded (yes/no)
		$limitedext = array(".jpg",".png",".jpeg",".JPEG",".JPG", ".PNG", ".gif", ".GIF"); //Extensions you want files uploaded limited to.

          //check if the directory exists or not.
          if (!is_dir("$upload_dir")) {
	     	die ("The directory $upload_dir doesn't exist");
          }
          //check if the directory is writable.
          if (!is_writeable("$upload_dir")){
             die ("The directory $upload_dir is NOT writable, Please CHMOD (777)");
          }

          //check if no file selected.
          if (!is_uploaded_file($_FILES['fileUpload']['tmp_name']))
              return '';

          //check file extension
		  $extCheck = $ext;
          $extCheck = strrchr($_FILES['fileUpload']['name'],'.');
          if (($extlimit == "yes") && (!in_array($extCheck,$limitedext))) {
              echo("This file type is not supported. Please only upload .jpg, .jpeg, or .png files.");
              exit();
          }

          // $filename will hold the value of the file name submitted FROM the form.
          $filename =  date(YmdHis)."_".$_FILES['fileUpload']['name'];
          // Check if file is Already EXISTS.
          if(file_exists($upload_dir.$filename)){
             echo "Oops! The file named $filename already exists.";
             exit();
          }

          //Move the File to the Directory of your choice
          //move_uploaded_file('filename','destination') Moves afile to a new location.
          if (move_uploaded_file($_FILES['fileUpload']['tmp_name'],$upload_dir.$filename)) {
			  chmod($upload_dir.$filename, 0604);
              //tell the user that the file has been uploaded and make him alink.
              return $_ENV['PATH_WALLPOST'].$filename;

          } else {
                  return NULL;
          }
	}
	
	public function addProfilePhoto($username){
		$upload_dir = $_ENV['DIR_PROFILE'];   

		$size_bytes = 10240000; // File Size in bytes 

		$extlimit = "yes"; //Do you want to limit the extensions of files uploaded (yes/no)
		$limitedext = array(".jpg",".png",".jpeg",".JPG", ".PNG", ".JPEG",".gif", ".GIF"); //Extensions you want files uploaded limited to.

          //check if the directory exists or not.
          if (!is_dir("$upload_dir")) {
    		mkdir("$upload_dir", 0777, true);
		  }
	    
          //check if the directory is writable.
          if (!is_writeable("$upload_dir")){
             die ("The directory $upload_dir is NOT writable, Please CHMOD (777)");
          }

          //check if no file selected.
          if (!is_uploaded_file($_FILES['fileUpload']['tmp_name'])) {
                     return "no file";
		  }
              
          //check file extension
			$extCheck = $ext;
            $extCheck = strrchr($_FILES['fileUpload']['name'],'.');
            if (($extlimit == "yes") && (!in_array($extCheck,$limitedext))) {
              echo("This file type is not supported. Please only upload .jpg, .jpeg, .gif or .png files.");
              exit();
            }

            // $filename will hold the value of the file name submitted FROM the form.
            $filename =  date(YmdHis)."_".$username."_".$_FILES['fileUpload']['name'];
            // Check if file is Already EXISTS.
            if(file_exists($upload_dir.$filename)){
                echo "Oops! The file named $filename already exists.";
                exit();
            }

            //Move the File to the Directory of your choice
            //move_uploaded_file('filename','destination') Moves afile to a new location.
            if (move_uploaded_file($_FILES['fileUpload']['tmp_name'], $upload_dir.$filename)) {
				chmod($upload_dir.$filename, 0604);
				
                //tell the user that the file has been uploaded and make him alink.
				return $this->updateProfilePhoto($username,$filename);
						

            } else {
                // Photo not uploaded
                return NULL;
            }
	}

  public function updateUserPreferences($username, $preferences) {
    date_default_timezone_set('America/Toronto');
    
    $settings = '';
    $updates = array();

    if (!empty($preferences) && is_array($preferences)) { 
      foreach ($preferences as $key => $value) {
        $updates[$key] = ($value) ? 'yes' : 'no';
      }
       
      $settings = serialize($updates);
    }
       
    $stmt = $this->conn->prepare('UPDATE user_preference SET settings = :settings, date_modified = NOW() WHERE username = :username ');
    $stmt->bindParam(':settings', $settings);
    $stmt->bindParam(':username', $username);

    $result = $stmt->execute();
    
    if ($result) {
      return TRUE;
    } else {
      return NULL;
    }
  }
    
  public function getUserPreferences($username) {
        $stmt = $this->conn->prepare('SELECT settings FROM user_preference WHERE username = :username');
        $stmt->bindParam(':username', $username);
        if ($stmt->execute())  {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          $prefs = array();
          $preferences = unserialize($row['settings']);

          if (!empty($preferences) && is_array($preferences)) {
            foreach ($preferences as $key => $value) {
              $prefs[$key] = $value;
            }
          }
    
          return $prefs;
        } else {
            return NULL;
        }
    }
	
	public function getSetting($key) {
		$stmt = $this->conn->prepare('SELECT setting_value FROM setting WHERE setting_key = :key');
 
        $stmt->bindParam(':key', $key);
        $stmt->execute();
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        
        if (isset($row) && $row) {
        	return $row['setting_value'];
        } else {
        	return NULL;
        }
	}
	
	public function forgotPassword($username){
      
      	$stmt = $this->conn->prepare('SELECT username, email FROM user WHERE username = :username');
 
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        
        if (isset($row) && $row) {
          // Found user with the username
          // Generate new reset code 
          $email		= $row['email'];
         	$reset_code = sha1(uniqid(rand(), true));
         	date_default_timezone_set("America/Toronto");
         	$reset_dt = date('Y-m-d H:i:s');
         	$reset_code_active = 1;
         	
         	$stmt = $this->conn->prepare('UPDATE user SET reset_code = :reset_code, reset_code_active = :reset_code_active, reset_dt = :reset_dt WHERE username = :username');
    		  $stmt->bindParam(':username',$username);
    		  $stmt->bindParam(':reset_code',$reset_code);
    		  $stmt->bindParam(':reset_code_active',$reset_code_active);
    		  $stmt->bindParam(':reset_dt',$reset_dt);
    		  $stmt->execute();
      
         	$from_name 	= $this->getSetting('config_name');
         	$from_url	= $_ENV['HTTP_CATALOG'];
         	$subject 	= 'Password Reset';
	     	  $message 	= '<p>Someone just requested that the password be reset for your account at '.$from_name.'.</p><p>If this was a mistake, just ignore this email and nothing will happen.</p><p>To reset your password, click the following link:</p>
	   <p><a href="'.$from_url.'reset?c='.$reset_code.'">Reset My Password</a></p>';
         
         	$this->sendEmail($username, $email, $subject, $message, 0);
         	return 'success';
        } else {
            // user not existed with the email
            return 'not_username';
        }      
   }
   
   public function sendEmail($username, $email,$subject,$message, $id = 0) {
		$resident_info	= $this->getUserByUsername($username);
		$building_info	= $this->getBuildingInfo($resident_info['bid']);
		
		if (isset($building_info) && $building_info) {
			$from_name		= $building_info['name'];
			$from_email		= $building_info['email'];
			$from_logo 		= $building_info['image'] ? $building_info['image'] : 'jazlife0.png';
			$logo_href		= $_ENV['HTTP_IMAGE'].$from_logo;
			$from_url		= $_ENV['HTTP_CATALOG'];
			$from_address	= str_replace(",",",<br/>",$this->getSetting('config_address'));
		} else {
			$from_name 		= $this->getSetting('config_name');
			$from_email 	= $this->getSetting('config_email');
			$from_logo 		= $this->getSetting('config_logo');
			$logo_href		= $_ENV['HTTP_IMAGE0'].$from_logo;
			$from_url		= $_ENV['HTTP_CATALOG'];
			$from_address	= str_replace(",",",<br/>",$this->getSetting('config_address'));
		}
		
		$tracker 		= $from_url.'/track.php?log=true&campaign_id='.$id.'&date='.date('Y-m-d').'&email=' . urlencode( $email );
		
		$fullname		= isset($resident_info['fullname']) ? $resident_info['fullname'] : 'Resident';

		$html = '
			<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>'.$subject.'</title>
        
        <!--[if gte mso 6]>
        <style>
            table.mcnFollowContent {width:100% !important;}
            table.mcnShareContent {width:100% !important;}
        </style>
        <![endif]-->
<style type="text/css">
body {
	color: #000000;
	font-family: Arial, Helvetica, sans-serif;
}
body, td, th, input, textarea, select, a {
	font-size: 12px;
}
h2 {
	font-size: 18px;
}
p {
	margin-top: 0px;
	margin-bottom: 20px;
}
a, a:visited, a b {
	color: #378DC1;
	text-decoration: underline;
	cursor: pointer;
}
a:hover {
	text-decoration: none;
}
a img {
	border: none;
}
#container {
	width: 680px;
}
#logo {
	margin-bottom: 20px;
}
.footer {
	float:left;
	font-size:11px;
	font-weight:lighter;
	margin:5px;
}
.footer a {
	font-size:11px;
	font-weight:lighter;
}
.message {
	padding: 0px 5px;
	font-size: 12px;
	font-style:italic;
	border-bottom: 1px solid #ccc;
}
table.list {
	border-collapse: collapse;
	width: 100%;
	border-top: 1px solid #DDDDDD;
	border-left: 1px solid #DDDDDD;
	margin-bottom: 20px;
}
table.list td {
	border-right: 1px solid #DDDDDD;
	border-bottom: 1px solid #DDDDDD;
}
table.list thead td {
	background-color: #EFEFEF;
	padding: 0px 5px;
}
table.list thead td a, .list thead td {
	text-decoration: none;
	color: #222222;
	font-weight: bold;
}
table.list tbody td a {
	text-decoration: underline;
}
table.list tbody td {
	vertical-align: top;
	padding: 0px 5px;
}
table.list .left {
	text-align: left;
	padding: 7px;
}
table.list .right {
	text-align: right;
	padding: 7px;
}
table.list .center {
	text-align: center;
	padding: 7px;
}
</style>
</head>
<body>
<div id="container">
  <img border="0" src="'.$tracker.'" width="1" height="1" />
  <table class="list">
    
    <tbody>
      <tr>
        <td class="center" style="background-color: #EFEFEF;" width="77"><img src="'.$logo_href.'"></td>
        <td class="left">
        <table class="list">
        	<thead>
      		<tr>
        		<td class="left" colspan="2"><h2>'.$subject.'</h2></td>
      		</tr>
    		</thead>
        </table>';
        
	  
	    $html .= '<br/><p>Dear '.$fullname.',</p><p>'.html_entity_decode($message, ENT_QUOTES, 'UTF-8').'</p>
	       
	    <br/>
<div class="footer"><hr><i>Copyright &copy; '.date('Y').' '.$from_name. ', All rights reserved.</i><br/><br/>Private and Confidential: This email was sent to '.$fullname.' at '.$email.' who is a registered resident/owner at '.$from_name.'<br/><br/>Our mailing address is:<br/>'.$from_address.'
<br/><br/>   
	    </div>
	        
        </td>
      </tr>
    </tbody>
    </table>
    
</body>
</html>';	


  $mg = Mailgun\Mailgun::create($_ENV['MAILGUN_API_KEY']);

  $mg->messages()->send('jazlife.com', [
    'from'    => 'info@jazlife.com',
    'to'      => $email,
    'subject' => $subject,
    'text'    => strip_tags(html_entity_decode($html)),
    'html'    => $html
  ]);
	
	return TRUE;

}
	
   
   	public function addProspect($building, $management) {
   		$response = array();
   		
   		if (!isset($building) || $building == '') {
   			return 'not_building';
   		} elseif (!isset($management) || $management == '') {
   			return 'not_management';
   		} else {
   			
   			$building 	= ucfirst($building);
   			$management	= ucfirst($management);
   			date_default_timezone_set("America/Toronto");
	 		$date_added = date('Y-m-d H:i:s');
	 		$ip 		= $_SERVER['REMOTE_ADDR'];
	 		$source		= 'iPhone App';
   			
   			// insert query
            $stmt = $this->conn->prepare('INSERT INTO prospects SET building = :building, management = :management, date_added = :date_added, ip = :ip, source = :source');
            $stmt->bindParam(':management',$management);
            $stmt->bindParam(':building',$building);
            $stmt->bindParam(':ip',$ip);
            $stmt->bindParam(':date_added',$date_added);
            $stmt->bindParam(':source',$source);
 
            $result = $stmt->execute();
 
            // Check for successful insertion
            if ($result) {
                // Prospect successfully inserted
                $username 	= 'davidfeldt';
                $email		= 'david@myjazlife.com';
                $subject	= 'Prospect FROM iPhone App';
                $message 	= 'Building: '.$building.'<br/>'.'Management Company: '.$management.'<br/>'.'IP Address: '.$ip;
                $this->sendEmail($username, $email, $subject, $message, 0);
                return 'valid';
            } else {
            	return 'error';
            }
   		}
   	}

	public function createUser($firstname, $lastname, $email, $password) {
        $response = array();
 
        // First check if user already existed in db
        if (!$this->isUserExists($email)) {
        
        	$username = strtolower($email);
        	
            // Generating password hash
            $password_hash = $this->create_hash($password);
 
            // Generating API key
            $api_key = $this->generateApiKey();
            
            // Create fullname
            $firstname 	= ucfirst($firstname);
            $lastname	= ucfirst($lastname);
            $fullname	= $firstname." ".$lastname;
            date_default_timezone_set("America/Toronto");
            $date_added	= date('Y-m-d');
 			
            // insert query
            $stmt = $this->conn->prepare('INSERT INTO user SET username = :username, firstname = :firstname, lastname = :lastname, fullname = :fullname, email = :email, password = :password, apiKey = :apiKey, status = 0, date_added = :date_added');
            $stmt->bindParam(':username',$username);
            $stmt->bindParam(':firstname',$firstname);
            $stmt->bindParam(':lastname',$lastname);
            $stmt->bindParam(':fullname',$fullname);
            $stmt->bindParam(':email',$email);
            $stmt->bindParam(':password',$password_hash);
            $stmt->bindParam(':apiKey',$api_key);
            $stmt->bindParam(':date_added',$date_added);
 
            $result = $stmt->execute();
 
            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return $_ENV['USER_CREATED_SUCCESSFULLY'];
            } else {
                // Failed to create user
                return $_ENV['USER_CREATE_FAILED'];
            }
        } else {
            // User with same email already existed in the db
            return $_ENV['USER_ALREADY_EXISTED'];
        }
 
        return $response;
    }
    
    public function changePassword($username, $current_password, $new_password) {
        $response = array();
 
       	  if ($this->checkLogin($username,$current_password) != 'valid') {
       	  	return 'not_password';
       	  } else {
        	
            // Generating password hash
            $password_hash = $this->create_hash($new_password);
 
            // Generating new API key
            //$api_key = $this->generateApiKey();
            
 			
            // insert query
            $stmt = $this->conn->prepare('UPDATE user SET password = :password WHERE username = :username');
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
 

    public function checkLogin($username, $password) {
        // fetching user by username
        $stmt = $this->conn->prepare("SELECT username, password FROM user WHERE username = :username AND status = '1'");
 
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        
        if (isset($row) && $row) {
            // Found user with the username
            // Now verify the password
            
            if ($this->validate_password($password, $row['password'])) {
                // User password is correct
                return 'valid';
            } else {
                // user password is incorrect
                return 'not_password';
            }
        } else {
            // user not existed with the email
            return 'not_username';
        }
    }
 

    private function isUserExists($email) {
        $stmt = $this->conn->prepare('SELECT username FROM user WHERE email = :email');
        $stmt->bindParam(':email', $email);
        $stmt->execute();
        $row = $stmt->fetch();
        if ($row) { return TRUE; } else { return FALSE; }

    }
    
    private function isUserNameTaken($username) {
        $stmt = $this->conn->prepare('SELECT username FROM user WHERE LOWER(username) = :username');
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $row = $stmt->fetch();
        if ($row) { return TRUE; } else { return FALSE; }
    }
    
    private function createUserName($username,$x = '') {
    	if (!$this->isUserNameTaken($username)) {
    		return $username;
    	} else {
    		if (!$x) { $x = 1;} else { $x++; }
    		$this->createUserName($username,$x);
    	}
    
    }
 

    public function getUserByUsername($username) {
        $stmt = $this->conn->prepare('SELECT u.username, u.bid, u.firstname, u.lastname, u.fullname, u.email, u.apiKey, u.status, u.phone, u.mobilephone, u.resident_type, u.privacy, u.date_added, u.profilepic, u.unit, b.name FROM user u LEFT JOIN building b ON u.bid = b.bid WHERE u.username = :username');
        $stmt->bindParam(':username', $username);
        if ($stmt->execute()) {
            $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $row = $stmt->fetch();
            
            return $row;
        } else {
            return NULL;
        }
    }

        
    public function getProfileByUsername($username) {
        $stmt = $this->conn->prepare('SELECT username, bid, firstname, lastname, fullname, email, phone, mobilephone, profilepic, resident_type, privacy, unit, bio, twitter, facebook, linkedin FROM user WHERE username = :username');
        $stmt->bindParam(':username', $username);
        if ($stmt->execute()) {
        	$stmt->setFetchMode(PDO::FETCH_ASSOC);
            $row = $stmt->fetch();
            return $row;
        } else {
            return NULL;
        }
    }
    
    public function getBuildingInfo($bid) {
        $stmt = $this->conn->prepare('SELECT * FROM building WHERE bid = :bid');
        $stmt->bindParam(':bid', $bid);
        if ($stmt->execute()) {
        	$stmt->setFetchMode(PDO::FETCH_ASSOC);
            $row = $stmt->fetch();
            return $row;
        } else {
            return NULL;
        }
    }
    
    
    public function updateProfile($username, $data) {
      date_default_timezone_set('America/Toronto');

      if (!empty($data['firstname']) && !empty($data['lastname'])) {
        $firstname = ucwords(trim($data['firstname']));
        $lastname = ucwords(trim($data['lastname']));
        $fullname = $firstname." ".$lastname;

        $stmt = $this->conn->prepare('UPDATE user SET firstname = :firstname, lastname = :lastname, fullname = :fullname, date_modified=NOW()  WHERE username = :username');
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':firstname',$firstname);
        $stmt->bindParam(':lastname',$lastname);
        $stmt->bindParam(':fullname',$fullname);
        $stmt->execute();

      }

      if (!empty($data['email'])) {
        $email = strtolower($data['email']);
        $stmt = $this->conn->prepare('UPDATE user SET email = :email, date_modified=NOW() WHERE username = :username');
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':email',$email);
        $stmt->execute();
      }

      if (!empty($data['phone'])) {
        $phone = $data['phone'];
        $stmt = $this->conn->prepare('UPDATE user SET phone = :phone, date_modified=NOW() WHERE username = :username');
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':phone',$phone);
        $stmt->execute();
      }

      if (!empty($data['mobilephone'])) {
        $stmt = $this->conn->prepare('UPDATE user SET mobilephone = :mobilephone, date_modified=NOW() WHERE username = :username');
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':mobilephone',$data['mobilephone']);
        $stmt->execute();
      }

      if (!empty($data['privacy'])) {
        $stmt = $this->conn->prepare('UPDATE user SET privacy = :privacy, date_modified=NOW() WHERE username = :username');
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':privacy',$data['privacy']);
        $stmt->execute();
      }

      return true;
    }
    
    public function updateProfilePhoto($username, $profilepic) {
    	$stmt = $this->conn->prepare('UPDATE user SET profilepic = :profilepic WHERE username = :username');
    	$stmt->bindParam(':username',$username);
    	$stmt->bindParam(':profilepic',$profilepic);
    	if ($stmt->execute())  {
        	return $profilepic;
        } else {
            return NULL;
        }
    }
    
    public function getPermissionsByUsername($username) {
        $stmt = $this->conn->prepare('SELECT settings FROM user_preference WHERE username = :username');
        $stmt->bindParam(':username', $username);
        if ($stmt->execute())  {
        	$stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          $prefs = array();
          $preferences = unserialize($row['settings']);

          if (!empty($preferences) && is_array($preferences)) {
            foreach ($preferences as $key => $value) {
              $prefs[$key] = $value;
            }
          }
    
          return $prefs;
        } else {
            return NULL;
        }
    }
 
 	

    public function getResidentName($username) {
        $stmt = $this->conn->prepare('SELECT fullname FROM user WHERE username = :username');
        $stmt->bindParam(':username', $username);
        if ($stmt->execute()) {
        	$stmt->setFetchMode(PDO::FETCH_ASSOC);
            $row = $stmt->fetch();
            return $row['fullname'];
        } else {
            return NULL;
        }
    }
  
    public function getResidentAvatar($username) {
        $stmt = $this->conn->prepare('SELECT profilepic FROM user WHERE username = :username');
        $stmt->bindParam(':username', $username);
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $row = $stmt->fetch();
            return $row['profilepic'];
        } else {
            return NULL;
        }
    }


// display Status

    function displayStatus($status) {
		switch ($status) {
			case 's':
				$display = 'Submitted';
				break;
			case 'i':
				$display = 'In Progress';
				break;
			case 'r':
				$display = 'Resolved';
				break;
			default:
				$display = $status;
				break;
		}

		return $display;
	}

	function displayUrgency($urgency) {
		switch ($urgency) {
			case 'h':
				$display = 'High';
				break;
			case 'm':
				$display = 'Medium';
				break;
			case 'l':
				$display = 'Low';
				break;
			default:
				$display = $urgency;
				break;
		}

		return $display;
	}

// Reservations

  private function getResourceName($resource_id) {
        $stmt = $this->conn->prepare('SELECT name FROM reservation_resources WHERE resource_id = :resource_id');
        $stmt->bindParam(':resource_id', $resource_id);
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $row = $stmt->fetch();
            return $row['name'];
        } else {
            return 'Unknown';
        }
    }

  private function getResourceCategory($resource_id) {
        $stmt = $this->conn->prepare('SELECT c.name FROM facility c LEFT JOIN reservation_resources r ON c.facility_id = r.facility_id WHERE r.resource_id = :resource_id');
        $stmt->bindParam(':resource_id', $resource_id);
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $row = $stmt->fetch();
            return $row['name'];
        } else {
            return 'N/A';
        }
    }

  private function getReservedTimeSlots($rescode) {
    $post_data = array();
    $stmt = $this->conn->prepare("SELECT * FROM reservation_timeslot WHERE rescode = :rescode ORDER BY timeslot_id ASC");
    
    $stmt->bindParam(':rescode', $rescode);
      
    if ($stmt->execute()) {
      $slots = $stmt->fetchAll(PDO::FETCH_ASSOC);
      foreach ($slots AS $row) {
        $post_data [] = array (
          'timeslot_id' => (int)$row['timeslot_id'],
          'resource_id' => (int)$row['resource_id'],
          'label'       => $row['label'],
          'rescode'     => $row['rescode'],
          'date'        => date('m/d/Y', strtotime($row['date'])),
        );
      }
    }

    return $post_data;
  }

  private function numberOfReservations($username) {
        $profile  = $this->getProfileByUsername($username);
        $bid      = $profile['bid'];
        $parent_id= 0;
        $stmt     = $this->conn->prepare('SELECT COUNT(*) AS total FROM reservation WHERE username = :username AND bid = :bid');
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':bid', $bid);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return (int)$row['total'];
        } else {
          return 0;
        }
      }

  function getReservationComments($reservation_id) {
      $comments = array();
      date_default_timezone_set('America/Toronto');
      $now = date('Y-m-d H:i:s');

      $stmt = $this->conn->prepare("SELECT * FROM reservation_log WHERE reservation_id = :reservation_id ORDER BY log_id ASC");
        $stmt->bindParam(':reservation_id', $reservation_id);

        if ($stmt->execute()) {
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          if ($results) {
            foreach ($results AS $row) {
              $comments [] = array (
                'id'          => (int)$row['log_id'],
                'comment'     => $row['comment'],
                'date_added'  => $this->dateTimeDiff($row['date_added']),
                'fullname'    => $this->getResidentName($row['username']),
                'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar($row['username']),
              );
            }
          } else {
            $comments [] = array (
                'id'          => 0,
                'comment'     => 'No existing comments. Click above to add your comment.',
                'date_added'  => $this->dateTimeDiff($now),
                'fullname'    => $this->getResidentName(''),
                'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar(''),
              );
          }
      }

      return $comments;
    }

  public function getReservation($reservation_id)  {
      $post_data  = array();

      $stmt = $this->conn->prepare("SELECT * FROM reservation WHERE reservation_id = :reservation_id");
      $stmt->bindParam(':reservation_id',$reservation_id);
        
      if ($stmt->execute()) {
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        $post_data = array (
          'id'              => (int)$row['reservation_id'],
          'bid'             => (int)$row['bid'],
          'username'        => $row['username'],
          'dateAdded'       => $this->dateTimeDiff($row['date_added']),
          'resourceName'    => $this->getResourceName($row['resource_id']),
          'resourceCategory'=> $this->getResourceCategory($row['resource_id']),
          'status'          => $row['resstatus'],
          'rescode'         => $row['rescode'],
          'timeslots'       => $this->getReservedTimeSlots($row['rescode']),
          'description'     => $row['description'],
          'comments'        => $this->getReservationComments($row['reservation_id'])
          
        );
      }

      return $post_data;
  }

  public function getAllReservations($username,$page = 1)  {
    $page = (isset($page)) ? $page : 1;
      $start = ($page - 1) * $_ENV['LIMIT'];
      $limit = $_ENV['LIMIT'];
    
      $profile  = $this->getProfileByUsername($username);
      $bid    = $profile['bid'];
      $post_data  = array();

      $stmt = $this->conn->prepare("SELECT * FROM reservation WHERE username = :username AND bid = :bid ORDER BY date_added DESC LIMIT $start, $limit");
    
      $stmt->bindParam(':username', $username);
      $stmt->bindParam(':bid',$bid);
        
      if ($stmt->execute()) {
        $reservations = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($reservations AS $row) {
          $post_data [] = array (
            'id'              => (int)$row['reservation_id'],
            'bid'             => (int)$row['bid'],
            'username'        => $row['username'],
            'dateAdded'       => $this->dateTimeDiff($row['date_added']),
            'resourceName'    => $this->getResourceName($row['resource_id']),
            'resourceCategory'=> $this->getResourceCategory($row['resource_id']),
            'status'          => $row['resstatus'],
            'rescode'         => $row['rescode'],
            'timeslots'       => $this->getReservedTimeSlots($row['rescode']),
            'description'     => $row['description'],
            'comments'        => $this->getReservationComments($row['reservation_id'])
            
          );
        }
      } 
      
      $lastCount = $start + $limit;
      $maxCount  = $this->numberOfMaintenanceRequests($username);
      $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;
      
      return array(
        'nextPage'  => $nextPage,
        'reservations'  => $post_data,
      );
  }

// Marketplace

	function getMarketplaceComments($marketplace_id) {
    	$comments = array();
      date_default_timezone_set('America/Toronto');
      $now = date('Y-m-d H:i:s');

    	$stmt = $this->conn->prepare("SELECT * FROM marketplace_log WHERE marketplace_id = :marketplace_id ORDER BY log_id ASC");
        $stmt->bindParam(':marketplace_id', $marketplace_id);

        if ($stmt->execute()) {
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          if ($results) {
            foreach ($results AS $row) {
              $comments [] = array (
                'id'          => (int)$row['log_id'],
                'comment'     => $row['comment'],
                'date_added'  => $this->dateTimeDiff($row['date_added']),
                'fullname'    => $this->getResidentName($row['username']),
                'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar($row['username']),
              );
            }
          } else {
            $comments [] = array (
                'id'          => 0,
                'comment'     => 'No existing comments. Click above to add your comment.',
                'date_added'  => $this->dateTimeDiff($now),
                'fullname'    => $this->getResidentName(''),
                'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar(''),
              );
          }
      }

      return $comments;
    }

    function getMarketplaceImages($marketplace_id) {
    	$images = array();

    	$stmt = $this->conn->prepare("SELECT image FROM marketplace_image WHERE marketplace_id = :marketplace_id ");
        $stmt->bindParam(':marketplace_id', $marketplace_id);

        if ($stmt->execute()) {
    		$results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    		foreach ($results AS $row) {
    			array_push($images, $_ENV['HTTP_SERVER'].$row['image']);
	    	}
    	}

    	return $images;
    }

    private function numberOfMarketplaceItems($bid) {
        $isAvailable = 1;
        $stmt     = $this->conn->prepare('SELECT COUNT(*) AS total FROM marketplace WHERE isAvailable = :isAvailable AND bid = :bid');
        $stmt->bindParam(':isAvailable', $isAvailable);
        $stmt->bindParam(':bid', $bid);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return (int)$row['total'];
        } else {
          return 0;
        }
      }

    public function getAllMarketplaceItems($bid,$page = 1)	{
		  $page = (isset($page)) ? $page : 1;
    	$start = ($page - 1) * $_ENV['LIMIT'];
    	$limit = $_ENV['LIMIT'];
		  $isAvailable = 1;

    	$post_data	= array();

		  $stmt = $this->conn->prepare("SELECT * FROM marketplace WHERE bid = :bid AND isAvailable = :isAvailable ORDER BY date_added DESC ");
        $stmt->bindParam(':bid',$bid);
        $stmt->bindParam(':isAvailable',$isAvailable);
        
        if ($stmt->execute()) {
    		$posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    		foreach ($posts AS $post) {
    			if ($post['type'] == 's') {
					$price = (is_numeric($post['price']) && $post['price']) ? '$'.number_format($post['price'],2) : 'Contact for price';
				} else {
					$price = '';
				}
				$type = ($post['type'] == 's') ? 'For Sale' : 'Wanted';

  			$post_data [] = array (
  				'id'			=> (int)$post['marketplace_id'],
  				'bid'			=> (int)$post['bid'],
  				'username'		=> $post['username'],
  				'dateAdded'		=> $this->dateTimeDiff($post['date_added']),
  				'description'	=> $post['description'],
  				'blurb'         => substr(strip_tags(html_entity_decode($post['description'])), 0, 50).' ...',
  				'category'		=> (int)$post['category_id'],
  				'categoryName'  => $this->getCategoryName($post['category_id'],'marketplace'),
  				'images'		=> $this->getMarketplaceImages($post['marketplace_id']),
  				'comments'		=> $this->getMarketplaceComments($post['marketplace_id']),
					'title' 		=> $post['title'],
					'price'			=> $price,
					'type'			=> $type,
					'views'			=> $post['views'],
					'is_new'		=> $post['is_new'],
					'fullname'		=> $this->getResidentName($post['username'])
    				
    			);
    		}
      } 

      $lastCount = $start + $limit;
      $maxCount  = $this->numberOfMarketplaceItems($bid);
      $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;
      
      return array(
        'nextPage'  => $nextPage,
        'items'     => $post_data,
      );
        

   	}
	
	public function deleteMarketplaceItem($username, $id) {
		$stmt = $this->conn->prepare('DELETE FROM marketplace WHERE marketplace_id = :id AND username = :username');
        $stmt->bindParam(':id', $id);
        $stmt->bindParam(':username',$username);
        if ($stmt->execute()) {
            return TRUE;
        } else {
            return NULL;
        }
	
	}

// Maintenance Requests

	function getMaintenanceComments($maintenance_id) {
    	$comments = array();
      date_default_timezone_set('America/Toronto');
      $now = date('Y-m-d H:i:s');

    	$stmt = $this->conn->prepare("SELECT * FROM maintenance_log WHERE maintenance_id = :maintenance_id ORDER BY log_id ASC");
        $stmt->bindParam(':maintenance_id', $maintenance_id);

        if ($stmt->execute()) {
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          if ($results) {
            foreach ($results AS $row) {
              $comments [] = array (
                'id'          => (int)$row['log_id'],
                'comment'     => $row['comment'],
                'date_added'  => $this->dateTimeDiff($row['date_added']),
                'fullname'    => $this->getResidentName($row['username']),
                'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar($row['username']),
              );
            }
          } else {
            $comments [] = array (
                'id'          => 0,
                'comment'     => 'No existing comments. Click above to add your comment.',
                'date_added'  => $this->dateTimeDiff($now),
                'fullname'    => $this->getResidentName(''),
                'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar(''),
              );
          }
      }

      return $comments;
    }

    function getMaintenanceImages($maintenance_id) {
    	$images = array();

    	$stmt = $this->conn->prepare("SELECT image FROM maintenance_image WHERE maintenance_id = :maintenance_id ");
        $stmt->bindParam(':maintenance_id', $maintenance_id);

        if ($stmt->execute()) {
    		$results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    		foreach ($results AS $row) {
    			array_push($images, $_ENV['HTTP_SERVER'].$row['image']);
	    	}
    	}

    	return $images;
    }

    function getMaintenanceFirstImage($maintenance_id) {
      $image = $_ENV['HTTP_SERVER'].'img/default-placeholder-300x300.png';

      $stmt = $this->conn->prepare("SELECT image FROM maintenance_image WHERE maintenance_id = :maintenance_id ");
        $stmt->bindParam(':maintenance_id', $maintenance_id);

        if ($stmt->execute()) {
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          if (!empty($results[0])) {
            $image = $_ENV['HTTP_SERVER'].$results[0]['image'];
          }
        }

      return $image;
    }

	public function addMaintenanceRequest($username, $data) {
		date_default_timezone_set("America/Toronto");
		
		$profile 		= $this->getProfileByUsername($username);
    	$bid			= $profile['bid'];
    	$unit 			= $profile['unit'];
    	$date_added		= date('Y-m-d H:i:s');
    	$description	= !empty($data['description']) ? $data['description'] : '';
    	$enterpermission= !empty($data['enterPermission']) ? $data['enterPermission'] : 0;
    	$urgency 		= !empty($data['urgency']) ? $data['urgency'] : 'l';
    	$instruction 	= !empty($data['instruction']) ? $data['instruction'] : '';
    	$category_id 	= !empty($data['category_id']) ? $data['category_id'] : 0;
    	$status 		= !empty($data['status']) ? $data['status'] : 's';
    	$date_noticed	= !empty($data['dateNoticed']) ? date('Y-m-d', strtotime($data['dateNoticed'])) : $date_added;
    	$image 			= !empty($data['image']) ? $data['image'] : '';
		
		$stmt = $this->conn->prepare("INSERT INTO maintenance SET username = :username, bid = :bid, unit = :unit, date_added = :date_added, description = :description, enterpermission = :enterpermission, urgency = :urgency, instruction = :instruction, category_id = :category_id, status = :status, date_noticed = :date_noticed, date_modified = :date_added, assigned_to = '', is_new = '1'");
    	$stmt->bindParam(':username',$username);
    	$stmt->bindParam(':date_noticed',$date_noticed);
    	$stmt->bindParam(':date_added',$date_added);
    	$stmt->bindParam(':description',$description);
    	$stmt->bindParam(':enterpermission',$enterpermission);
    	$stmt->bindParam(':urgency',$urgency);
    	$stmt->bindParam(':instruction',$instruction);
    	$stmt->bindParam(':category_id',$category_id);
    	$stmt->bindParam(':status',$status);
    	$stmt->bindParam(':unit',$unit);
    	$stmt->bindParam(':bid',$bid);
    	
    	$result = $stmt->execute();

    	$maintenance_id = $this->conn->lastInsertId();
    	
    	if ($result) {
			// save Base 64 string as image.    	
	    	if ($image) {
	    		$uploadDir	= $_ENV['DIR_MAINTENANCEREPORT'];
	    		$uploadPath = $_ENV['PATH_MAINTENANCEREPORT'];
	    		$img 		= str_replace(' ', '+', $image);
				$imgData 	= base64_decode($img);
				$filename 	= $username . '_' . uniqid() . '.jpg';
				$imgPath 	= $uploadPath . $filename;
				$file 		= $uploadDir . $filename;
				$success = file_put_contents($file, $imgData);

				if ($success) {
					// add to maintenance_image
					$stmt = $this->conn->prepare("INSERT INTO maintenance_image SET maintenance_id = :maintenance_id, username = :username, image = :image, date_added = :date_added, bid = :bid ");
					$stmt->bindParam(':maintenance_id',$maintenance_id);
					$stmt->bindParam(':username',$username);
			    	$stmt->bindParam(':image',$imgPath);
			    	$stmt->bindParam(':date_added',$date_added);
			    	$stmt->bindParam(':bid',$bid);
			    	$result = $stmt->execute();
				}
	    	}

    		return TRUE;
		} else {
			return NULL;
		}
	}
  
  
  public function addComment($username, $id, $comment, $type) {
    date_default_timezone_set("America/Toronto");

    if (!empty($comment) && !empty($id)) {

      $date_added = date('Y-m-d H:i:s');
      $profile    = $this->getProfileByUsername($username);
      $bid        = $profile['bid'];
      $fullname   = $profile['fullname'];
      $notify     = 1;
      $comment_id = 0;

      $sql = "INSERT INTO {$type}_log SET username = :username, fullname = :fullname, bid = :bid, notify = :notify, date_added = :date_added, comment = :comment, {$type}_id = :id";
        
      $stmt = $this->conn->prepare($sql);
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':fullname',$fullname);
      $stmt->bindParam(':bid',$bid);
      $stmt->bindParam(':notify',$notify);
      $stmt->bindParam(':date_added',$date_added);
      $stmt->bindParam(':comment',$comment);
      $stmt->bindParam(':id',$id);
      
      $result = $stmt->execute();
      
      if ($result) {

        return $this->conn->lastInsertId();
      } else {
        return NULL;
      }
    } else {
      return false;
    }
  
  } 
  
	
	
	public function updateMaintenanceRequest($id, $username, $date_created, $description, $enterpermission, $urgency, $instruction, $category, $status, $date_noticed) {
		$file = '';
		$thumbNailPathName = '';
    	
    	if (isset($_FILES['fileUpload'])) {	
    	// upload the file if it exists
		$file = $this->uploadMaintenanceImage();
    	// Create a Thumbnail if an image exists
		if ($file != "no file") {
			$imgArr = explode('/', $file);
			$imgNameOnly = $imgArr[sizeof($imgArr)-1];
			$folderPath = "";
			for ($i=0; $i<sizeof($imgArr)-1; $i++) {
				$folderPath .=  $imgArr[$i] . "/" ;
			}
			$thumbNailPathName = $folderPath . "thumb_" . $imgNameOnly;
			$imgType = getImgType($imgNameOnly);
			// Instantiate the thumbnail
			$tn=new Thumbnail(150,150);
			// Load an image into a string (this could be FROM a database)
			$image=file_get_contents($file);
			// Load the image data
			$tn->loadData($image,$imgType);
			// Build the thumbnail and store as a file
			$tn->buildThumb($thumbNailPathName);
			
			//update filenames in DB table
			$stmt = $this->conn->prepare('UPDATE maintenance SET photo = :photo, thumb = :thumb WHERE id = :id');
    		$stmt->bindParam(':photo',$file);
    		$stmt->bindParam(':thumb',$thumbNailPathName);
    		$stmt->bindParam(':id',$id);
    		$result = $stmt->execute();
		}
		}
		
		$stmt = $this->conn->prepare('UPDATE maintenance SET username = :username, date_created = :date_created, description = :description, enterpermission = :enterpermission, urgency = :urgency, 
		instruction = :instruction, category = :category, status = :status, date_noticed = :date_noticed WHERE id = :id');
    	$stmt->bindParam(':username',$username);
    	$stmt->bindParam(':date_noticed',$date_noticed);
    	$stmt->bindParam(':date_created',$date_created);
    	$stmt->bindParam(':description',$description);
    	$stmt->bindParam(':enterpermission',$enterpermission);
    	$stmt->bindParam(':urgency',$urgency);
    	$stmt->bindParam(':instruction',$instruction);
    	$stmt->bindParam(':category',$category);
    	$stmt->bindParam(':status',$status);
    	$stmt->bindParam(':id',$id);
    	$result = $stmt->execute();
    	
    	
    	if ($result) {
    		return TRUE;
    	} else {
    		return NULL;
    	}
	
	}

  private function numberOfMaintenanceRequests($username) {
        $profile  = $this->getProfileByUsername($username);
        $bid      = $profile['bid'];
        $parent_id= 0;
        $stmt     = $this->conn->prepare('SELECT COUNT(*) AS total FROM maintenance WHERE username = :username AND bid = :bid');
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':bid', $bid);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return (int)$row['total'];
        } else {
          return 0;
        }
      }

  public function getMaintenanceRequest($maintenance_id)  {

    $post_data  = array();

    $stmt = $this->conn->prepare("SELECT * FROM maintenance WHERE maintenance_id = :maintenance_id");
        $stmt->bindParam(':maintenance_id',$maintenance_id);
        
        if ($stmt->execute()) {
          $post = $stmt->fetch(PDO::FETCH_ASSOC);

          $post_data [] = array (
            'id'              => (int)$post['maintenance_id'],
            'bid'             => (int)$post['bid'],
            'username'        => $post['username'],
            'dateCreated'     => $this->dateTimeDiff($post['date_added']),
            'description'     => $post['description'],
            'enterPermission' => (int)$post['enterpermission'],
            'urgency'         => $post['urgency'],
            'displayUrgency'  => $this->displayUrgency($post['urgency']),
            'instruction'     => $post['instruction'],
            'category'        => (int)$post['category_id'],
            'status'          => $post['status'],
            'displayStatus'   => $this->displayStatus($post['status']),
            'dateNoticed'     => $this->dateTimeDiff($post['date_noticed']),
            'categoryName'    => $this->getCategoryName($post['category_id'],'maintenance'),
            'images'          => $this->getMaintenanceImages($post['maintenance_id']),
            'image'           => $this->getMaintenanceFirstImage($post['maintenance_id']),
            'comments'        => $this->getMaintenanceComments($post['maintenance_id']),
            
          );

      } 
        
        return $post_data;
    }
	
	public function getAllMaintenanceRequests($username,$page = 1)	{
		$page = (isset($page)) ? $page : 1;
    	$start = ($page - 1) * $_ENV['LIMIT'];
    	$limit = $_ENV['LIMIT'];
		
		  $profile 	= $this->getProfileByUsername($username);
    	$bid		= $profile['bid'];
    	$post_data	= array();

		$stmt = $this->conn->prepare("SELECT * FROM maintenance WHERE username = :username AND bid = :bid ORDER BY date_added DESC LIMIT $start, $limit");
		
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':bid',$bid);
        
        if ($stmt->execute()) {
      		$posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
      		foreach ($posts AS $post) {
      			$post_data [] = array (
      				'id'              => (int)$post['maintenance_id'],
      				'bid'             => (int)$post['bid'],
      				'username'        => $post['username'],
      				'dateCreated'     => $this->dateTimeDiff($post['date_added']),
      				'description'     => $post['description'],
      				'enterPermission'	=> (int)$post['enterpermission'],
      				'urgency'         => $post['urgency'],
      				'displayUrgency'	=> $this->displayUrgency($post['urgency']),
      				'instruction'     => $post['instruction'],
      				'category'        => (int)$post['category_id'],
      				'status'          => $post['status'],
      				'displayStatus'		=> $this->displayStatus($post['status']),
      				'dateNoticed'     => $this->dateTimeDiff($post['date_noticed']),
      				'categoryName'    => $this->getCategoryName($post['category_id'],'maintenance'),
      				'images'          => $this->getMaintenanceImages($post['maintenance_id']),
              'image'           => $this->getMaintenanceFirstImage($post['maintenance_id']),
      				'comments'        => $this->getMaintenanceComments($post['maintenance_id']),
      				
      			);
      		}
        } 
        
        $lastCount = $start + $limit;
        $maxCount  = $this->numberOfMaintenanceRequests($username);
        $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;
        
        return array(
          'nextPage'  => $nextPage,
          'requests'  => $post_data,
        );
   	}
	
	public function deleteMaintenanceRequest($username, $id) {
		$stmt = $this->conn->prepare('DELETE FROM maintenance WHERE id = :id AND username = :username');
        $stmt->bindParam(':id', $id);
        $stmt->bindParam(':username',$username);
        if ($stmt->execute()) {
            return TRUE;
        } else {
            return NULL;
        }
	
	}
	
// Front Desk Instructions

	public function getFrontdeskComments($frontdesk_id) {
  	$comments = array();
    date_default_timezone_set('America/Toronto');
    $now = date('Y-m-d H:i:s');

  	$stmt = $this->conn->prepare("SELECT * FROM frontdesk_log WHERE frontdesk_id = :frontdesk_id ORDER BY log_id ASC");
      $stmt->bindParam(':frontdesk_id', $frontdesk_id);

      if ($stmt->execute()) {
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          if ($results) {
            foreach ($results AS $row) {
              $comments [] = array (
                'id'          => (int)$row['log_id'],
                'comment'     => $row['comment'],
                'date_added'  => $this->dateTimeDiff($row['date_added']),
                'fullname'    => $this->getResidentName($row['username']),
                'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar($row['username']),
              );
            }
          } else {
            $comments [] = array (
                'id'          => 0,
                'comment'     => 'No existing comments. Click above to add your comment.',
                'date_added'  => $this->dateTimeDiff($now),
                'fullname'    => $this->getResidentName(''),
                'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar(''),
              );
          }
      }

      return $comments;
    }

	public function addFrontDeskInstruction($username, $data) {
		
		$profile 	= $this->getProfileByUsername($username);
    	$bid		= $profile['bid'];
    	
		$stmt = $this->conn->prepare('INSERT INTO frontdesk SET username = :username, bid = :bid, date_created = :date_created, description = :description, startdate = :startdate, enddate = :enddate, 
		noenddate = :noenddate, category = :category');
    	$stmt->bindParam(':username',$username);
    	$stmt->bindParam(':date_created',$date_created);
    	$stmt->bindParam(':description',$description);
    	$stmt->bindParam(':startdate',$startdate);
    	$stmt->bindParam(':enddate',$enddate);
    	$stmt->bindParam(':noenddate',$noenddate);
    	$stmt->bindParam(':category',$category);
    	$stmt->bindParam(':bid',$bid);
    	
    	$result = $stmt->execute();
    	
    	
    	if ($result) {
    		return TRUE;
    	} else {
    		return NULL;
    	}
	}
	
	public function updateFrontDeskInstruction($id, $username, $date_created, $description, $startdate, $enddate, $noenddate, $category) {
		$stmt = $this->conn->prepare('UPDATE frontdesk SET username = :username, date_created = :date_created, description = :description, startdate = :startdate, enddate = :enddate, noenddate = :noenddate,
										category = :category WHERE id = :id');
    	$stmt->bindParam(':username',$username);
    	$stmt->bindParam(':date_created',$date_created);
    	$stmt->bindParam(':description',$description);
    	$stmt->bindParam(':startdate',$startdate);
    	$stmt->bindParam(':enddate',$enddate);
    	$stmt->bindParam(':noenddate',$noenddate);
    	$stmt->bindParam(':category',$category);
    	$stmt->bindParam(':id',$id);
    	$result = $stmt->execute();
    	
    	if ($result) {
    		return TRUE;
    	} else {
    		return NULL;
    	}
	
	}

  private function numberOfFrontdeskInstructions($username) {
    $profile  = $this->getProfileByUsername($username);
    $bid      = $profile['bid'];
    $parent_id= 0;
    $stmt     = $this->conn->prepare('SELECT COUNT(*) AS total FROM frontdesk WHERE username = :username AND bid = :bid');
    $stmt->bindParam(':username', $username);
    $stmt->bindParam(':bid', $bid);
    $post_data = array();
    if ($stmt->execute()) {
      $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return (int)$row['total'];
    } else {
      return 0;
    }
  }

  public function getFrontDeskInstruction($frontdesk_id)  {
    $post_data  = array ();

    $stmt = $this->conn->prepare("SELECT * FROM frontdesk WHERE frontdesk_id = :frontdesk_id");
    $stmt->bindParam(':frontdesk_id', $frontdesk_id);
    
    if ($stmt->execute()) {
      $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $post = $stmt->fetch();
      $post_data = array (
          'id'            => (int)$post['frontdesk_id'],
          'bid'           => (int)$post['bid'],
          'username'      => $post['username'],
          'dateAdded'     => date('m/d/Y', strtotime($post['date_added'])),
          'description'   => $post['description'],
          'blurb'         => substr(strip_tags(html_entity_decode($post['description'])), 0, 50).' ...',
          'category_id'   => (int)$post['category_id'],
          'startDate'     => date('m/d/Y', strtotime($post['start_date'])),
          'endDate'       => date('m/d/Y', strtotime($post['end_date'])),
          'noEnddate'     => $post['no_enddate'],
          'categoryName'  => $this->getCategoryName($post['category_id'],'frontdesk'),
          'comments'      => $this->getFrontdeskComments($post['frontdesk_id'])
      );
    }

    return $post_data;
  }

  public function getAllFrontDeskInstructions($username,$page = 1)  {
    $page = (isset($page)) ? $page : 1;
    $start = ($page - 1) * $_ENV['LIMIT'];
    $limit = $_ENV['LIMIT'];
      
    $profile  = $this->getProfileByUsername($username);
    $bid    = $profile['bid'];
    $post_data  = array ();

    $stmt = $this->conn->prepare("SELECT * FROM frontdesk WHERE username = :username AND bid = :bid ORDER BY date_added DESC LIMIT $start, $limit");
    $stmt->bindParam(':username', $username);
    $stmt->bindParam(':bid',$bid);
    
    if ($stmt->execute()) {
      $posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
      foreach ($posts AS $post) {
        $post_data [] = array (
            'id'           	=> (int)$post['frontdesk_id'],
            'bid'          	=> (int)$post['bid'],
            'username'     	=> $post['username'],
            'dateAdded'     => date('m/d/Y', strtotime($post['date_added'])),
            'description' 	=> $post['description'],
            'blurb'         => substr(strip_tags(html_entity_decode($post['description'])), 0, 50).' ...',
            'category_id'   => (int)$post['category_id'],
            'startDate'    	=> date('m/d/Y', strtotime($post['start_date'])),
            'endDate'       => date('m/d/Y', strtotime($post['end_date'])),
            'noEnddate'    	=> $post['no_enddate'],
            'categoryName'	=> $this->getCategoryName($post['category_id'],'frontdesk'),
            'comments'      => $this->getFrontdeskComments($post['frontdesk_id'])
        );
      }
    } 

    $lastCount = $start + $limit;
    $maxCount  = $this->numberOfFrontdeskInstructions($username);
    $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;
    
    return array(
      'nextPage'  => $nextPage,
      'instructions'     => $post_data,
    );
  }
	
	public function deleteFrontDeskInstruction($username, $frontdesk_id) {
		$stmt = $this->conn->prepare('DELETE FROM frontdesk WHERE frontdesk_id = :frontdesk_id AND username = :username');
        $stmt->bindParam(':frontdesk_id', $frontdesk_id);
        $stmt->bindParam(':username', $username);
        if ($stmt->execute()) {
            return TRUE;
        } else {
            return NULL;
        }
	}


// Incident Reports

	function getIncidentComments($incident_id) {
    	$comments = array();
      date_default_timezone_set('America/Toronto');
      $now = date('Y-m-d H:i:s');

    	$stmt = $this->conn->prepare("SELECT * FROM incident_log WHERE incident_id = :incident_id ORDER BY log_id ASC");
        $stmt->bindParam(':incident_id', $incident_id);

        if ($stmt->execute()) {
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          if ($results) {
            foreach ($results AS $row) {
              $comments [] = array (
                'id'          => (int)$row['log_id'],
                'comment'     => $row['comment'],
                'date_added'  => $this->dateTimeDiff($row['date_added']),
                'fullname'    => $this->getResidentName($row['username']),
                'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar($row['username']),
              );
            }
          } else {
            $comments [] = array (
                'id'          => 0,
                'comment'     => 'No existing comments. Click above to add your comment.',
                'date_added'  => $this->dateTimeDiff($now),
                'fullname'    => $this->getResidentName(''),
                'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar(''),
              );
          }
      }

      return $comments;
    }

    function getIncidentImages($incident_id) {
    	$images = array();

    	$stmt = $this->conn->prepare("SELECT image FROM incident_image WHERE incident_id = :incident_id ");
        $stmt->bindParam(':incident_id', $incident_id);

        if ($stmt->execute()) {
    		$results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    		foreach ($results AS $row) {
    			array_push($images, $_ENV['HTTP_SERVER'].$row['image']);
	    	}
    	}

    	return $images;
    }

    function getIncidentFirstImage($incident_id) {
      $image = $_ENV['HTTP_SERVER'].'img/default-placeholder-300x300.png';

      $stmt = $this->conn->prepare("SELECT image FROM incident_image WHERE incident_id = :incident_id ");
        $stmt->bindParam(':incident_id', $incident_id);

        if ($stmt->execute()) {
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          if (!empty($results[0])) {
            $image = $_ENV['HTTP_SERVER'].$results[0]['image'];
          }
        }

      return $image;
    }

	public function addIncidentReport($username, $data) {
		date_default_timezone_set("America/Toronto");
		
		$profile 		= $this->getProfileByUsername($username);
    	$bid			= $profile['bid'];
    	$date_added		= date('Y-m-d H:i:s');
    	$description	= !empty($data['description']) ? $data['description'] : '';
    	$date_noticed	= !empty($data['dateNoticed']) ? date('Y-m-d', strtotime($data['dateNoticed'])) : $date_added;
    	$time_noticed	= !empty($data['timeNoticed']) ? $data['timeNoticed'] : '';
    	$category_id 	= !empty($data['category_id']) ? $data['category_id'] : 0;
    	$status 		= !empty($data['status']) ? $data['status'] : 's';
    	$image 			= !empty($data['image']) ? $data['image'] : '';
		
		$stmt = $this->conn->prepare("INSERT INTO incident SET username = :username, bid = :bid, date_added = :date_added, description = :description, category_id = :category_id, status = :status, date_noticed = :date_noticed, time_noticed = :time_noticed, date_modified = :date_added, adminid = '0', is_new = '1'");
    	$stmt->bindParam(':username',$username);
    	$stmt->bindParam(':bid',$bid);
    	$stmt->bindParam(':date_added',$date_added);
    	$stmt->bindParam(':description',$description);
    	$stmt->bindParam(':category_id',$category_id);
    	$stmt->bindParam(':date_noticed',$date_noticed);
    	$stmt->bindParam(':time_noticed',$time_noticed);
    	$stmt->bindParam(':status',$status);
    	
    	$result = $stmt->execute();

    	$incident_id = $this->conn->lastInsertId();
    	
    	if ($result) {
			// save Base 64 string as image.    	
	    	if ($image) {
	    		$uploadDir	= $_ENV['DIR_INCIDENTREPORT'];
	    		$uploadPath = $_ENV['PATH_INCIDENTREPORT'];
	    		$img 		= str_replace(' ', '+', $image);
				$imgData 	= base64_decode($img);
				$filename 	= $username . '_' . uniqid() . '.jpg';
				$imgPath 	= $uploadPath . $filename;
				$file 		= $uploadDir . $filename;
				$success = file_put_contents($file, $imgData);

				if ($success) {
					// add to maintenance_image
					$stmt = $this->conn->prepare("INSERT INTO incident_image SET incident_id = :incident_id, username = :username, image = :image, date_added = :date_added, bid = :bid ");
					$stmt->bindParam(':incident_id',$incident_id);
					$stmt->bindParam(':username',$username);
			    	$stmt->bindParam(':image',$imgPath);
			    	$stmt->bindParam(':date_added',$date_added);
			    	$stmt->bindParam(':bid',$bid);
			    	$stmt->execute();
				}
	    	}

    		return TRUE;
		} else {
			return NULL;
		}
	}
	
	
	public function updateIncidentReport($id, $username, $date_created, $date_noticed, $time_noticed, $description, $category) {
		$status = 's'; // sent
		
		if (isset($_FILES['fileUpload'])) {	
    	// upload the file if it exists
		$file = $this->uploadIncidentImage();
    	// Create a Thumbnail if an image exists
		if ($file != "no file") {
			$imgArr = explode('/', $file);
			$imgNameOnly = $imgArr[sizeof($imgArr)-1];
			$folderPath = "";
			for ($i=0; $i<sizeof($imgArr)-1; $i++) {
				$folderPath .=  $imgArr[$i] . "/" ;
			}
			$thumbNailPathName = $folderPath . "thumb_" . $imgNameOnly;
			$imgType = getImgType($imgNameOnly);
			// Instantiate the thumbnail
			$tn=new Thumbnail(150,150);
			// Load an image into a string (this could be FROM a database)
			$image=file_get_contents($file);
			// Load the image data
			$tn->loadData($image,$imgType);
			// Build the thumbnail and store as a file
			$tn->buildThumb($thumbNailPathName);
			
			//update filenames in DB table
			$stmt = $this->conn->prepare('UPDATE maintenance SET photo = :photo, thumb = :thumb WHERE id = :id');
    		$stmt->bindParam(':photo',$file);
    		$stmt->bindParam(':thumb',$thumbNailPathName);
    		$stmt->bindParam(':id',$id);
    		$result = $stmt->execute();
		}
		}
		
		$stmt = $this->conn->prepare('UPDATE incident SET username = :username, date_created = :date_created, date_noticed = :date_noticed, time_noticed = :time_noticed, description = :description, 
		category = :category, status = :status WHERE id = :id');
    	$stmt->bindParam(':username',$username);
    	$stmt->bindParam(':date_noticed',$date_noticed);
    	$stmt->bindParam(':time_noticed',$time_noticed);
    	$stmt->bindParam(':date_created',$date_created);
    	$stmt->bindParam(':description',$description);
    	$stmt->bindParam(':category',$category);
    	$stmt->bindParam(':status',$status);
    	$stmt->bindParam(':id',$id);
    	$result = $stmt->execute();
    	    	
    	if ($result) {
    		return TRUE;
    	} else {
    		return NULL;
    	}
	
	}

  private function getCategoryName($category_id, $type) {
      $stmt = $this->conn->prepare("SELECT category_name FROM {$type}_categories WHERE category_id = :category_id");
      $stmt->bindParam(':category_id', $category_id);
      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return $row['category_name'];
      } else {
          return NULL;
      }
  }

  private function numberOfIncidentReports($username) {
        $profile  = $this->getProfileByUsername($username);
        $bid      = $profile['bid'];
        $parent_id= 0;
        $stmt     = $this->conn->prepare('SELECT COUNT(*) AS total FROM incident WHERE username = :username AND bid = :bid');
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':bid', $bid);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return (int)$row['total'];
        } else {
          return 0;
        }
      }
	
  public function getIncidentReport($incident_id)  {
    $post_data  = array ();

    $stmt = $this->conn->prepare("SELECT * FROM incident WHERE incident_id = :incident_id");
    $stmt->bindParam(':incident_id',$incident_id);
    
    if ($stmt->execute()) {
      $post = $stmt->fetch(PDO::FETCH_ASSOC);

        $post_data  = array (
            'id'            => (int)$post['incident_id'],
            'bid'           => (int)$post['bid'],
            'username'      => $post['username'],
            'dateCreated'   => $this->dateTimeDiff($post['date_added']),
            'description'   => $post['description'],
            'blurb'         => substr(strip_tags(html_entity_decode($post['description'])), 0, 50).' ...',
            'category'      => (int)$post['category_id'],
            'status'        => $post['status'],
            'dateNoticed'   => date('m/d/Y', strtotime($post['date_noticed'])),
            'timeNoticed'   => $post['time_noticed'],
            'categoryName'  => $this->getCategoryName($post['category_id'],'incident'),
            'displayStatus' => $this->displayStatus($post['status']),
            'images'        => $this->getIncidentImages($post['incident_id']),
            'image'         => $this->getIncidentFirstImage($post['incident_id']),
            'comments'      => $this->getIncidentComments($post['incident_id']),
        );
    } 
        
    return $post_data;
  }

	public function getAllIncidentReports($username,$page = 1)	{
		$page = (isset($page)) ? $page : 1;
    $start = ($page - 1) * $_ENV['LIMIT'];
    $limit = $_ENV['LIMIT'];
    	
    $profile 	= $this->getProfileByUsername($username);
    $bid		= $profile['bid'];
    $post_data	= array ();

		$stmt = $this->conn->prepare("SELECT * FROM incident WHERE username = :username AND bid = :bid ORDER BY date_added DESC LIMIT $start, $limit");
    $stmt->bindParam(':username', $username);
    $stmt->bindParam(':bid',$bid);
		
    if ($stmt->execute()) {
    	$posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    	foreach ($posts AS $post) {
    		$post_data [] = array (
    				'id'            => (int)$post['incident_id'],
    				'bid'           => (int)$post['bid'],
    				'username'      => $post['username'],
    				'dateCreated'   => $this->dateTimeDiff($post['date_added']),
    				'description'   => $post['description'],
    				'blurb'         => substr(strip_tags(html_entity_decode($post['description'])), 0, 50).' ...',
    				'category'      => (int)$post['category_id'],
    				'status'        => $post['status'],
    				'dateNoticed'   => date('m/d/Y', strtotime($post['date_noticed'])),
    				'timeNoticed'   => $post['time_noticed'],
    				'categoryName'	=> $this->getCategoryName($post['category_id'],'incident'),
    				'displayStatus'	=> $this->displayStatus($post['status']),
    				'images'		    => $this->getIncidentImages($post['incident_id']),
            'image'         => $this->getIncidentFirstImage($post['incident_id']),
    				'comments'      => $this->getIncidentComments($post['incident_id']),
    		);
    	}
    } 
        
    $lastCount = $start + $limit;
    $maxCount  = $this->numberOfIncidentReports($username);
    $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;
        
    return array(
      'nextPage'  => $nextPage,
      'incidents' => $post_data,
    );
	}
	
	public function deleteIncidentReport($username, $id) {
		$stmt = $this->conn->prepare('DELETE FROM incident WHERE id = :id AND username = :username');
        $stmt->bindParam(':id', $id);
        $stmt->bindParam(':username', $username);
        if ($stmt->execute()) {
            return TRUE;
        } else {
            return NULL;
        }
	
	}

// News

  private function numberOfNews($bid) {
        $status = 1;
        $stmt     = $this->conn->prepare('SELECT COUNT(*) AS total FROM news WHERE status = :status AND bid = :bid');
        $stmt->bindParam(':status', $status);
        $stmt->bindParam(':bid', $bid);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return (int)$row['total'];
        } else {
          return 0;
        }
      }

  public function getAllNews($bid = 1,$page = 1) {
    $page = (isset($page)) ? $page : 1;
    $start = ($page - 1) * $_ENV['LIMIT'];
    $limit = $_ENV['LIMIT'];
    $status = 1;
      
    $news = array ();
      
    $stmt = $this->conn->prepare("SELECT * FROM news WHERE bid = :bid AND status = :status ORDER BY news_id DESC LIMIT $start, $limit");
    $stmt->bindParam(':bid', $bid);
    $stmt->bindParam(':status', $status);
      
    if ($stmt->execute()) {
      $msgs = $stmt->fetchAll(PDO::FETCH_ASSOC);
      foreach ($msgs AS $row) {

        $user = $this->getUserByUsername($row['author']);
      
        $news [] = array (
          
            'id'            => (int)$row['news_id'],
            'start_date'    => date('m/d/Y',strtotime($row['start_date'])),
            'end_date'      => date('m/d/Y',strtotime($row['end_date'])),
            'type'          => $row['type'],
            'author'        => $row['author'],
            'avatar'        => $_ENV['HTTP_SERVER'].$user['profilepic'],
            'author_name'   => $row['author_name'] ? $row['author_name'] : $this->getResidentName($row['author']),
            'category_id'   => (int)$row['category_id'],
            'title'         => $row['title'],
            'blurb'         => substr(strip_tags(html_entity_decode($row['description'])), 0, 100).'...',
            'description'   => $row['description'],
            'image'         => $row['image'],
            'status'        => (int)$row['status'],
            'status_display'=> ($row['status']) ? 'Visible' : 'Hidden',
            'date_added'    => date('m/d/Y',strtotime($row['date_added'])),
            'viewed'        => $row['viewed'],
            'likes'         => $row['likes']
          );
      }
    }

    $lastCount = $start + $limit;
    $maxCount  = $this->numberOfNews($bid);
    $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;
      
    return array(
      'nextPage'  => $nextPage,
      'news'     => $news,
    );

  }

// People

  private function numberOfPeople($bid) {
        $status = 1;
        $stmt     = $this->conn->prepare('SELECT COUNT(*) AS total FROM user WHERE status = :status AND bid = :bid');
        $stmt->bindParam(':status', $status);
        $stmt->bindParam(':bid', $bid);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return (int)$row['total'];
        } else {
          return 0;
        }
      }

  public function getAllPeople($bid = 1,$page = 1) {
    $page = (isset($page)) ? $page : 1;
    $start = ($page - 1) * $_ENV['LIMIT'];
    $limit = $_ENV['LIMIT'];
    $status = 1;
      
    $people = array ();
      
    $stmt = $this->conn->prepare("SELECT * FROM user WHERE bid = :bid AND status = :status AND privacy != 's' ORDER BY firstname ASC LIMIT $start, $limit");
    $stmt->bindParam(':bid', $bid);
    $stmt->bindParam(':status', $status);
      
    if ($stmt->execute()) {
      $msgs = $stmt->fetchAll(PDO::FETCH_ASSOC);
      foreach ($msgs AS $row) {
      
        $people [] = array (
          
            'user_id'       => (int)$row['user_id'],
            'username'	    => $row['username'],
            'fullname'      => trim($row['fullname']),
            'privacy'       => $row['privacy'],
            'avatar'        => $_ENV['HTTP_SERVER'].$row['profilepic'],
            'unit'          => $row['unit'],
            'title'         => $row['title'],
            'phone'         => $row['phone'],
            'phone'         => $row['phone'],
            'mobilephone'   => $row['mobilephone'],
            'bio'           => $row['bio'],
            'twitter'       => $row['twitter'],
            'facebook'      => $row['facebook'],
            'linkedin'      => $row['linkedin'],
          );
      }
    }

    $lastCount = $start + $limit;
    $maxCount  = $this->numberOfPeople($bid);
    $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;
      
    return array(
      'nextPage'  => $nextPage,
      'people'     => $people,
    );

  }
	
// Messaging / mail

	public function addMessage($username, $userTo, $subject, $message) {
		
		$profile  	= $this->getProfileByUsername($username);
    $bid		    = $profile['bid'];
		$sentDate 	= date('Y-m-d H:i:s');
    $childid    = 0;
    $starred    = 0;
    $status     = 'unread';
    $userFrom   = $username;
		
		$stmt = $this->conn->prepare("INSERT INTO message SET owner = :owner, bid = :bid, sentDate = :sentDate, userTo = :userTo, userFrom = :userFrom, subject = :subject, message = :message, status = :status, childid = :childid, starred = :starred");
    $stmt->bindParam(':userTo',$userTo);
  	$stmt->bindParam(':userFrom',$userFrom);
  	$stmt->bindParam(':subject',$subject);
    $stmt->bindParam(':message',$message);
  	$stmt->bindParam(':status',$status);
    $stmt->bindParam(':sentDate',$sentDate);
    $stmt->bindParam(':owner',$userTo);
    $stmt->bindParam(':childid',$childid);
    $stmt->bindParam(':starred',$starred);
  	$stmt->bindParam(':bid',$bid);
  	
  	$result = $stmt->execute();
    	
    $stmt = $this->conn->prepare("INSERT INTO message SET owner = :owner, bid = :bid, sentDate = :sentDate, userTo = :userTo, userFrom = :userFrom, subject = :subject, message = :message, status = :status, childid = :childid, starred = :starred");
    $stmt->bindParam(':userTo',$userTo);
    $stmt->bindParam(':userFrom',$userFrom);
    $stmt->bindParam(':subject',$subject);
    $stmt->bindParam(':message',$message);
    $stmt->bindParam(':status',$status);
    $stmt->bindParam(':sentDate',$sentDate);
    $stmt->bindParam(':owner',$userFrom);
    $stmt->bindParam(':childid',$childid);
    $stmt->bindParam(':starred',$starred);
    $stmt->bindParam(':bid',$bid);
    
    $result = $stmt->execute();
    	
    if ($result) {
  		return TRUE;
  	} else {
   		return NULL;
    }
	}
	
	public function addReplyToMessage($username, $id, $message) {
	  date_default_timezone_set('America/Toronto');
		$msg = $this->getMessage($username, $id);
		
		if ($msg) {
      $oMessage     = $msg['message'];
      $oSubject     = $msg['subject'];
      $sentDate     = $msg['sentDate'];
      $userTo       = $msg['userFrom'];
      $userFrom     = $msg['userTo'];
      $fromFullname = $this->getResidentName($userFrom);
      
      $subject      = "Re: ".$oSubject;
        
      $totalMessage = $message."\n\n\n"
                    ."----- Original Message -----\n"
                    ."From: ".$fromFullname."\n"
                    ."Date: ".date('m/d/Y h:i a', strtotime($sentDate))."\n"
                    ."Subject: ".$oSubject."\n"
                    ."Message:\n".$oMessage;
        
      $result = $this->addMessage($username, $userTo, $subject, $totalMessage);
    	
  		if ($result) {
  			return TRUE;
  		} else {
  			return NULL;
  		}
  	} else {
  		return NULL;
  	}
	}	
	
	
	public function getMessage($username, $message_id)	{
		$stmt = $this->conn->prepare('SELECT * FROM message WHERE message_id = :message_id');
        $stmt->bindParam(':message_id', $message_id);
        if ($stmt->execute()) {
            $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $row = $stmt->fetch();
            $stmt = $this->conn->prepare("UPDATE message SET status = 'read' WHERE message_id = :message_id");
        	$stmt->bindParam(':message_id', $message_id);
            $stmt->execute();
            return $row;
        } else {
            return NULL;
        }
	}

  private function numberOfMessages($username) {
        $profile  = $this->getProfileByUsername($username);
        $bid      = $profile['bid'];
        $stmt     = $this->conn->prepare('SELECT COUNT(*) AS total FROM message WHERE owner = :username AND userTo = :username AND bid = :bid');
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':bid', $bid);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return (int)$row['total'];
        } else {
          return 0;
        }
      }

	public function getAllMessages($username,$page = 1) {
		$page = (isset($page)) ? $page : 1;
    	$start = ($page - 1) * $_ENV['LIMIT'];
    	$limit = $_ENV['LIMIT'];
    	
    	$messages = array ();
    	$profile  = $this->getProfileByUsername($username);
      	$bid      = $profile['bid'];
		  
      	$stmt = $this->conn->prepare("SELECT * FROM message WHERE owner = :username AND userTo = :username AND bid = :bid ORDER BY message_id DESC LIMIT $start, $limit");
		
      	$stmt->bindParam(':username', $username);
      	$stmt->bindParam(':bid', $bid);
		
	    if ($stmt->execute()) {
	  		$msgs = $stmt->fetchAll(PDO::FETCH_ASSOC);
    		foreach ($msgs AS $msg) {
    			
    			$fullnameFrom = $this->getResidentName($msg['userFrom']);
  				$fullnameTo 	 = $this->getResidentName($msg['userTo']);
  		
    			$messages [] = array (
    				
    				'owner'       => $msg['owner'],
          	'id'          => (int)$msg['message_id'],
          	'userTo'	    => $msg['userTo'],
          	'userFrom'	  => $msg['userFrom'],
            'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar($msg['userFrom']),
          	'fullname'	  => $fullnameFrom,
          	'sentDate'	  => $this->dateTimeDiff($msg['sentDate']),
          	'subject'	    => $msg['subject'],
          	'message'	    => $msg['message'],
            'blurb'       => substr(strip_tags(html_entity_decode($msg['message'])), 0, 30).' ...',
          	'status'	    => $msg['status']
    			);
    		}
	    }
	    
      $lastCount = $start + $limit;
      $maxCount  = $this->numberOfMessages($username);
      $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;
        
      return array(
        'nextPage'  => $nextPage,
        'messages' => $messages,
      );  

	}
	
	public function deleteMessage($username, $id) {
		$stmt = $this->conn->prepare('DELETE FROM message WHERE message_id = :id AND owner = :username');
        $stmt->bindParam(':id', $id);
        $stmt->bindParam(':username', $username);
        if ($stmt->execute()) {
            return TRUE;
        } else {
            return NULL;
        }
	
	}
	
// Notifications FROM building management / announcements

	public function getAllNotifications($bid,$page) {
    	$page = (isset($page)) ? $page : 1;
    	$start = ($page - 1) * $_ENV['LIMIT'];
    	$limit = $_ENV['LIMIT'];
    	date_default_timezone_set('America/Toronto');
    	
    	$post_data = array();
        $stmt = $this->conn->prepare("SELECT a.id, a.bid, a.who AS username, u.fullname,u.profilepic, a.date AS date_added, a.title, a.message FROM announcement a LEFT JOIN user u ON a.who = u.username WHERE a.bid = :bid ORDER BY a.date DESC LIMIT $start, $limit");
        $stmt->bindParam(':bid',$bid);
        
        if ($stmt->execute()) {
      		$posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
      		foreach ($posts AS $post) {
      			$post_data [] = array (
      				'id'         => (int)$post['id'],
      				'bid'        => (int)$post['bid'],
      				'username'   => $post['username'],
      				'fullname'	 => $post['fullname'],
          		'avatar'     => $_ENV['HTTP_SERVER'].$post['profilepic'],
      				'date_added' => date('m/d/Y', strtotime($post['date_added'])),
      				'title'      => $post['title'],
      				'message'    => $post['message']
      			);
      		}
        } 

        if ($post_data) {        
          return $post_data; 
        } else {
          return array(
            'id'         => 0,
            'bid'        => $bid,
            'username'   => '',
            'fullname'   => '',
            'avatar'     => $_ENV['HTTP_SERVER'].'img/profile/default.png',
            'date_added' => date('m/d/Y'),
            'title'      => 'No announcements',
            'message'    => 'There are no announcements currently'
            );
        }
    }
    
	
// Wall Posts

    function getMarketplaceMessage($marketplace_id) {
      $stmt = $this->conn->prepare('SELECT title, description, type, price FROM marketplace WHERE marketplace_id = :marketplace_id');
        $stmt->bindParam(':marketplace_id', $marketplace_id);
        if ($stmt->execute()) {
            $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $row = $stmt->fetch();
    
      if ($row['type'] == 's') {
        $price = (is_numeric($row['price']) && $row['price']) ? '$'.number_format($row['price'],2) : 'Contact for price';
      } else {
        $price = '';
      }
      
      $type = ($row['type'] == 's') ? 'For Sale' : 'Wanted';
      $title      = $row['title'].' '.$type;
      $description  = substr(strip_tags(html_entity_decode($row['description'])), 0, 150).' ...';
      return $title.' | Price: '.$price.' | '.$description;
    }
  }

    function getPostImages($post_id) {
    	$images = array();

    	$stmt = $this->conn->prepare("SELECT image FROM wall_image WHERE post_id = :post_id ");
        $stmt->bindParam(':post_id', $post_id);

        if ($stmt->execute()) {
    		$results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    		foreach ($results AS $row) {
    			array_push($images, $_ENV['HTTP_SERVER'].$row['image']);
	    	}
    	}

    	return $images;
    }
    
    public function addPost($username, $message = '') {
    	date_default_timezone_set("America/Toronto");
	 	  $profile 	   = $this->getProfileByUsername($username);
    	
      $bid         = $profile['bid'];
      $fullname    = $profile['fullname'];
    	$type        = 'posts';
    	$date_added  = date('Y-m-d H:i:s');
      $type_id     = '0';
      $group_id    = '0';
      $parent_id   = '0';
      $abuse       = '0';
      $markabuse   = '0';
      $comments    = '0';
      $pin         = '0';
      $pin_expiry  = $date_added;
      $love        = '0';

      $result      = NULL;
    	$images     = array();

      $sql = "INSERT INTO `wall` SET username = :username, bid = :bid, fullname = :fullname, message = :message, type = :type, date_added = :date_added, type_id = :type_id, group_id = :group_id, parent_id = :parent_id, abuse = :abuse, markabuse = :markabuse, comments = :comments, pin = :pin, pin_expiry = :pin_expiry, love = :love";

      try {
  		
      	$stmt = $this->conn->prepare($sql);
      	$stmt->bindParam(':username',$username);
        $stmt->bindParam(':bid',$bid);
      	$stmt->bindParam(':fullname',$fullname);
      	$stmt->bindParam(':message',$message);
      	$stmt->bindParam(':type',$type);
        $stmt->bindParam(':date_added',$date_added);
        $stmt->bindParam(':type_id',$type_id);
        $stmt->bindParam(':group_id',$group_id);
        $stmt->bindParam(':parent_id',$parent_id);
        $stmt->bindParam(':abuse',$abuse);
        $stmt->bindParam(':markabuse',$markabuse);
        $stmt->bindParam(':comments',$comments);
        $stmt->bindParam(':pin',$pin);
        $stmt->bindParam(':pin_expiry',$pin_expiry);
        $stmt->bindParam(':love',$love);
      	
        $result = $stmt->execute();

        if ($result) {
          return $this->conn->lastInsertId();
        } else {
          return null;
        }

      }
      catch (PDOException $e) {
        die(htmlspecialchars ($e->getMessage()));
      }
    
    }

    private function getLikeCount($post_id) {
      $stmt = $this->conn->prepare('SELECT COUNT(*) AS total FROM wall_love WHERE post_id = :post_id');
      $stmt->bindParam(':post_id',$post_id);
      $post_data = array();
      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return (int)$row['total'] ? number_format($row['total'],0) : '';
      } else {
        return '';
      }
    }

    private function alreadyLikedPost($username, $post_id) {
      $stmt = $this->conn->prepare('SELECT COUNT(*) AS total FROM wall_love WHERE username = :username AND post_id = :post_id');
      $stmt->bindParam(':username', $username);
      $stmt->bindParam(':post_id',$post_id);
      $post_data = array();
      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return (int)$row['total'] > 0;
      } else {
        return 0;
      }
    }

    public function likePost($username, $bid, $post_id) {
      date_default_timezone_set("America/Toronto");
      $date_added   = date('Y-m-d H:i:s');
      $ip           = $_SERVER['REMOTE_ADDR'];
      $admin_new    = 1;

      if ($this->alreadyLikedPost($username, $post_id)) {
        // decrement count and remove from wall_love
        $stmt = $this->conn->prepare("DELETE FROM wall_love WHERE post_id = :post_id AND username = :username");
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':post_id',$post_id);
        $result = $stmt->execute();
        
        $stmt = $this->conn->prepare("UPDATE wall SET love = love - 1 WHERE post_id = :post_id");
        $stmt->bindParam(':post_id',$post_id);
        $result = $stmt->execute();

      } else {
        $stmt = $this->conn->prepare("INSERT INTO wall_love SET bid = :bid, post_id = :post_id, username = :username, date_added = :date_added, ip = :ip, admin_new = :admin_new");
        $stmt->bindParam(':date_added',$date_added);
        $stmt->bindParam(':ip',$ip);
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':post_id',$post_id);
        $stmt->bindParam(':bid',$bid);
        $stmt->bindParam(':admin_new',$admin_new);
        $result = $stmt->execute();
        
        $stmt = $this->conn->prepare("UPDATE wall SET love = love + 1 WHERE post_id = :post_id");
        $stmt->bindParam(':post_id',$post_id);
        $result = $stmt->execute();

      }
      
      return $this->getPostLikeData($username, $post_id);
      
    }

    private function getPostLikeData($username, $post_id) {
      $alreadyLikedPost = $this->alreadyLikedPost($username, $post_id);

      return array(
        'count'       => $this->getLikeCount($post_id),
        'id'          => (int)$post_id,
        'isLiked'     => $alreadyLikedPost
      );
    }

    public function reportPost($username, $bid, $post_id) {
      date_default_timezone_set("America/Toronto");
      $date_added   = date('Y-m-d H:i:s');
      $ip           = $_SERVER['REMOTE_ADDR'];
      $admin_new    = 1;

      if ($this->alreadyReportedPost($username, $post_id)) {
        // decrement count and remove from wall_love
        $stmt = $this->conn->prepare("DELETE FROM wall_spam WHERE post_id = :post_id AND username = :username");
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':post_id',$post_id);
        $result = $stmt->execute();
        
        $stmt = $this->conn->prepare("UPDATE wall SET markabuse = markabuse - 1 WHERE post_id = :post_id");
        $stmt->bindParam(':post_id',$post_id);
        $result = $stmt->execute();

      } else {
        $stmt = $this->conn->prepare("INSERT INTO wall_spam SET bid = :bid, post_id = :post_id, username = :username, date_added = :date_added, ip = :ip, admin_new = :admin_new");
        $stmt->bindParam(':date_added',$date_added);
        $stmt->bindParam(':ip',$ip);
        $stmt->bindParam(':username',$username);
        $stmt->bindParam(':post_id',$post_id);
        $stmt->bindParam(':bid',$bid);
        $stmt->bindParam(':admin_new',$admin_new);
        $result = $stmt->execute();
        
        $stmt = $this->conn->prepare("UPDATE wall SET markabuse = markabuse + 1 WHERE post_id = :post_id");
        $stmt->bindParam(':post_id',$post_id);
        $result = $stmt->execute();

      }
      
      return $this->getPostReportData($username, $post_id);
      
    }

    private function alreadyReportedPost($username, $post_id) {
      $stmt = $this->conn->prepare('SELECT COUNT(*) AS total FROM wall_spam WHERE username = :username AND post_id = :post_id');
      $stmt->bindParam(':username', $username);
      $stmt->bindParam(':post_id',$post_id);
      $post_data = array();
      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return (int)$row['total'] > 0;
      } else {
        return 0;
      }
    }

    private function getPostReportData($username, $post_id) {
      $alreadyReportedPost = $this->alreadyReportedPost($username, $post_id);

      return array(
        'id'          => (int)$post_id,
        'isReported'     => $alreadyReportedPost
      );
    }
    
    public function addPostComment($username, $id, $comment) {
    	date_default_timezone_set("America/Toronto");
      $post_id    = 0;
      $result     = null;
      $response   = array();
        
      $post_id    = $id;
      $profile 	 = $this->getProfileByUsername($username);
      $fullname  = $profile['fullname'];
      $bid		   = $profile['bid'];
      $date_added= date('Y-m-d H:i:s');
      $type        = 'posts';
      $message     = $comment;
      $type_id     = '0';
      $group_id    = '0';
      $parent_id   = $id;
      $abuse       = '0';
      $markabuse   = '0';
      $comments    = '0';
      $pin         = '0';
      $pin_expiry  = $date_added;
      $love        = '0';

      $result      = NULL;
      $images     = array();

      $sql = "INSERT INTO `wall` SET username = :username, bid = :bid, fullname = :fullname, message = :message, type = :type, date_added = :date_added, type_id = :type_id, group_id = :group_id, parent_id = :parent_id, abuse = :abuse, markabuse = :markabuse, comments = :comments, pin = :pin, pin_expiry = :pin_expiry, love = :love";

      try {
        
          $stmt = $this->conn->prepare($sql);
          $stmt->bindParam(':username',$username);
          $stmt->bindParam(':bid',$bid);
          $stmt->bindParam(':fullname',$fullname);
          $stmt->bindParam(':message',$message);
          $stmt->bindParam(':type',$type);
          $stmt->bindParam(':date_added',$date_added);
          $stmt->bindParam(':type_id',$type_id);
          $stmt->bindParam(':group_id',$group_id);
          $stmt->bindParam(':parent_id',$parent_id);
          $stmt->bindParam(':abuse',$abuse);
          $stmt->bindParam(':markabuse',$markabuse);
          $stmt->bindParam(':comments',$comments);
          $stmt->bindParam(':pin',$pin);
          $stmt->bindParam(':pin_expiry',$pin_expiry);
          $stmt->bindParam(':love',$love);
          
          $result = $stmt->execute();

        	if ($result) {

            // increment comment count
            $stmt = $this->conn->prepare("UPDATE wall SET comments = comments + 1 WHERE post_id = :post_id");
            $stmt->bindParam(':post_id', $post_id);
            $stmt->execute();

          } 

          
        }
        catch (PDOException $e) {
          die(htmlspecialchars ($e->getMessage()));
        }


      return $post_id;

    }
 
    
    private function numberOfComments($id) {
    	$stmt = $this->conn->prepare('SELECT COUNT(*) AS total FROM wall WHERE parent_id = :id');
      $stmt->bindParam(':id', $id);
      $post_data = array();
      if ($stmt->execute()) {
  		$stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
  		return number_format($row['total'],0);
      } else {
      	return 0;
      }
    }

    
    public function getPostComments($id) {
    	$markabuse = 0;
    	$stmt = $this->conn->prepare('SELECT post_id, bid, username, fullname, date_added, message, parent_id, type FROM wall WHERE parent_id = :id AND markabuse=:markabuse ORDER BY date_added  ASC');
        $stmt->bindParam(':id', $id);
        $stmt->bindParam(':markabuse', $markabuse);
        $post_data = array();
        if ($stmt->execute()) {
    		$posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    		foreach ($posts AS $post) {
    			$post_data [] = array (
    				'id'			    => (int)$post['post_id'],
    				'bid'			    => (int)$post['bid'],
    				'username'		=> $post['username'],
    				'fullname'    => $this->getResidentName($post['username']),
            'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar($post['username']),
    				'date_added'	=> $this->dateTimeDiff($post['date_added']),
    				'message'		  => $post['message']
    			);
    		}
        } 
        
        return $post_data;
    }

    private function numberOfPosts($username) {
        $profile  = $this->getProfileByUsername($username);
        $bid      = $profile['bid'];
        $parent_id= 0;
        $stmt     = $this->conn->prepare('SELECT COUNT(*) AS total FROM wall WHERE parent_id = :parent_id AND bid = :bid');
        $stmt->bindParam(':parent_id', $parent_id);
        $stmt->bindParam(':bid', $bid);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return (int)$row['total'];
        } else {
          return 0;
        }
      }
     
    public function getAllPosts($username,$page) {
    	$page = (isset($page)) ? $page : 1;
    	$start = ($page - 1) * $_ENV['LIMIT'];
    	$limit = $_ENV['LIMIT'];
    	
    	$profile 	= $this->getProfileByUsername($username);
    	$bid		= $profile['bid'];

    	$post_data = array();
    	
    	$pinned_posts = array ();
    	
    	$stmt = $this->conn->prepare("SELECT post_id, type_id, bid, username, date_added, comments, message, type, love FROM wall w WHERE parent_id = '0' AND bid = :bid AND pin = '1' ORDER BY date_added DESC");
    	$stmt->bindParam(':bid',$bid);
    	if ($stmt->execute()) {
    		$pinned_posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    	}
    	
        $stmt = $this->conn->prepare("SELECT post_id, type_id, bid, username, date_added, comments, message, type, love FROM wall WHERE parent_id = '0' AND bid = :bid AND pin = '0' ORDER BY date_added DESC LIMIT $start, $limit");
        $stmt->bindParam(':bid',$bid);
        
        if ($stmt->execute()) {
    		$posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    		
    		$posts = array_merge($pinned_posts,$posts);
    		
    		if ($posts) {
    			foreach ($posts AS $post) {

    				if ($post['type'] == 'posts') {
	    				$post_data [] = array (
	    					'id'          => (int)$post['post_id'],
	  						'bid'         => (int)$post['bid'],
	  						'username'		=> $post['username'],
	  						'fullname'		=> $this->getResidentName($post['username']),
	  						'avatar'	    => $_ENV['HTTP_SERVER'].$this->getResidentAvatar($post['username']),
	  						'date_added'	=> $this->dateTimeDiff($post['date_added']),
	  						'message'		  => $post['message'],
	  						'type'			  => $post['type'],
	  						'numComments' => $this->numberOfComments($post['post_id']),
	  						'iconComments'=> $post['comments'] ? 'ios-chatbubbles' : 'ios-chatbubbles-outline',
                'love'        => $this->getPostLikeData($username, $post['post_id']),
                'report'      => $this->getPostReportData($username, $post['post_id']),
	  						'comments'		=> $this->getPostComments($post['post_id']),
	  						'images'		  => $this->getPostImages($post['post_id']),
	  					);
    				}

    				if ($post['type'] == 'marketplace') {
	    				$post_data [] = array (
	    					'id'			    => (int)$post['post_id'],
	  						'bid'         => (int)$post['bid'],
	  						'username'		=> $post['username'],
	  						'fullname'		=> $this->getResidentName($post['username']),
	  						'avatar'      => $_ENV['HTTP_SERVER'].$this->getResidentAvatar($post['username']),
	  						'date_added'	=> $this->dateTimeDiff($post['date_added']),
	  						'message'     => $this->getMarketplaceMessage($post['type_id']),
	  						'type'        => $post['type'],
	  						'numComments' => $this->numberOfComments($post['post_id']),
	  						'iconComments'=> $post['comments'] ? 'ios-chatbubbles' : 'ios-chatbubbles-outline',
	  						'love'        => $this->getPostLikeData($username, $post['post_id']),
                'report'      => $this->getPostReportData($username, $post['post_id']),
	  						'comments'		=> $this->getPostComments($post['post_id']),
	  						'images'		  => $this->getMarketplaceImages($post['type_id']),
	  					);
    				}

    			}
    		} else {
  	    		$post_data [] = array (
  	    			'id'			       => 1,
  	    			'bid'			       => $bid,
  	    			'message'		     => 'No posts at this time. Please add a post!',
  	    			'date_added'	   => 'A few seconds ago',
  	    			'fullname'		   => 'System Administrator',
  	    			'avatar'		     => $_ENV['HTTP_SERVER'].'/images/jazlife0.png',
  	    			'image'			     => '',
  	    			'type'			     => 'posts',
  	    			'numComments'	   => 0,
  	    			'iconComments'   => $post['comments'] ? 'ios-chatbubbles' : 'ios-chatbubbles-outline',
              'love'           => $this->getPostLikeData($username, 0),
              'report'         => $this->getPostReportData($username, 0),
  	    			'comments'		   => array(),
  	    			'images'		     => array()
  	    		);
      		}
        } 

        $lastCount = $start + $limit;
        $maxCount  = $this->numberOfPosts($username);
        $nextPage  = ($lastCount < $maxCount) ? $page + 1 : null;
        
        return array(
          'nextPage'  => $nextPage,
          'posts'     => $post_data,
        );
    }
    
    
  public function deletePost($username, $id) {
		$stmt = $this->conn->prepare('DELETE FROM wall WHERE id = :id AND username = :username');
    $stmt->bindParam(':id', $id);
    $stmt->bindParam(':username',$username);
    if ($stmt->execute()) {
        return TRUE;
    } else {
        return NULL;
    }
	
	}
	

// Get categories for front desk instructions, maintenance requests and incident reports

	public function getCategories($username,$type)	{
		
		$profile 	  = $this->getProfileByUsername($username);
    $bid		    = $profile['bid'];
    $status     = 1;
		$categories = array();
		$table      = '';

    switch ($type) {
      case 'requests':
        $table = 'maintenance_categories';
        break;
      case 'instructions':
        $table = 'frontdesk_categories';
        break;
      case 'incidents':
        $table = 'incident_categories';
        break;
      case 'items':
        $table = 'marketplace_categories';
        break;
      default:
        $table = '';
    }

		if ($table) {
			
			$stmt = $this->conn->prepare("SELECT * FROM ".$table." WHERE bid = :bid AND status = :status ORDER BY category_name ASC");
      $stmt->bindParam(':bid',$bid);
			$stmt->bindParam(':status',$status);
    	if ($stmt->execute()) {
        $cats = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($cats AS $cat) {
          $categories[] = array (
            'id'    => (int)$cat['category_id'],
            'name'  => $cat['category_name']
          );
        }
    	} 
    }
    
    return $categories;
		
	}
	
// Resident autocomplete

	public function getResidentAutoComplete($username, $search = '') {
		$search 	= "%".strtolower($search)."%";
    	$profile 	= $this->getProfileByUsername($username);
    	$bid		= $profile['bid'];
    	
		$stmt = $this->conn->prepare("SELECT username, fullname FROM `user` WHERE userlevel < 8 AND bid = :bid AND LCASE(fullname) LIKE :search ORDER BY firstname ASC");
		$stmt->bindParam(':bid',$bid);
        $stmt->bindParam(':search',$search);
        
        if ($stmt->execute()) {
            	$stmt->setFetchMode(PDO::FETCH_ASSOC);
            	$rows = $stmt->fetchAll();
            
            	return $rows;
        } else {
            	return NULL;
        }
	}

// List of building managers

	public function getAllManagers($username,$page = 1)	{
		$page = (isset($page)) ? $page : 1;
    	$start = ($page - 1) * $_ENV['LIMIT'];
    	$limit = $_ENV['LIMIT'];
    	
    	$profile 	= $this->getProfileByUsername($username);
    	$bid		= $profile['bid'];
    	
    	$managers_data	= array ();

		$stmt = $this->conn->prepare("SELECT username, bid, title, firstname, lastname, fullname, email, phone, mobilephone, profilepic FROM user WHERE propertymanager = 'y' AND bid = :bid ORDER BY fullname ASC LIMIT $start, $limit");
		$stmt->bindParam(':bid',$bid);
        
        if ($stmt->execute()) {
    		$managers = $stmt->fetchAll(PDO::FETCH_ASSOC);
    		foreach ($managers AS $manager) {
    			$managers_data [] = array (
    				'username'		=> $manager['username'],
    				'bid'			=> $manager['bid'],
    				'title'			=> $manager['title'],
    				'firstname'		=> $manager['firstname'],
    				'lastname'		=> $manager['lastname'],
    				'fullname'		=> $manager['fullname'],
    				'email'			=> $manager['email'],
    				'phone'			=> $manager['phone'],
    				'mobilephone'	=> $manager['mobilephone'],
    				'profilepic'	=> $_ENV['HTTP_SERVER'].$manager['profilepic']
    			);
    		}
        
        } 
        
        return $managers_data;
	}
 
}
 
?>