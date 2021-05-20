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

  public function dateTimeDiff($dt) {
    date_default_timezone_set($_ENV['TIMEZONE']);
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

  public function getOrganizationName($orgId) {
    $stmt = $this->conn->prepare('SELECT name FROM organizations WHERE orgId = :orgId');
    $stmt->bindParam(':orgId', $orgId);
    if ($stmt->execute()) {
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return !empty($row['name']) ? $row['name'] : 'N/A';
    } else {
      return '';
    }
  }

  public function getEventName($eventId) {
    $stmt = $this->conn->prepare('SELECT name FROM events WHERE eventId = :eventId');
    $stmt->bindParam(':eventId', $eventId);
    if ($stmt->execute()) {
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return !empty($row['name']) ? $row['name'] : 'N/A';
    } else {
      return '';
    }
  }

  public function getMeetingName($meetingId) {
    $stmt = $this->conn->prepare('SELECT name FROM meetings WHERE meetingId = :meetingId');
    $stmt->bindParam(':meetingId', $meetingId);
    if ($stmt->execute()) {
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return !empty($row['name']) ? $row['name'] : 'N/A';
    } else {
      return '';
    }
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

  public function getMeetingsForEvent($eventId, $registrantId) {
      $response = array ();

      $stmt = $this->conn->prepare("SELECT * FROM meetings WHERE eventId = :eventId ORDER BY startDate ASC");
      $stmt->bindParam(':eventId', $eventId);

      if ($stmt->execute()) {
        $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($events AS $row) {

          $response [] = array (
              'meetingId'     => $row['meetingId'],
              'eventId'       => $row['eventId'],
              'startDate'     => date('m/d g:i a',strtotime($row['startDate'])),
              'endDate'       => date('m/d g:i a',strtotime($row['endDate'])),
              'location'      => $row['location'],
              'eventName'     => $this->getEventName($row['eventId']),
              'name'          => $row['name'],
              'capacity'      => $row['capacity'],
              'isRegistered'  => $this->isRegisteredForMeeting($row['meetingId'], $registrantId),
              'isCheckedIn'   => $this->isCheckedInForMeeting($row['meetingId'], $registrantId)
            );
        }
      }

      return $response;
    }

    public function getAllEvents($registrantId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d');
      $response = array ();

      $stmt = $this->conn->prepare("SELECT * FROM events WHERE endDate >= :endDate ORDER BY name ASC");
      $stmt->bindParam(':endDate', $now);

      if ($stmt->execute()) {
        $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($events AS $row) {

          $response [] = array (
              'eventId'       => $row['eventId'],
              'registrantId'  => $registrantId,
              'startDate'     => date('m/d/Y',strtotime($row['startDate'])),
              'endDate'       => date('m/d/Y',strtotime($row['endDate'])),
              'location'      => $row['location'],
              'orgId'         => $row['orgId'],
              'orgName'       => $this->getOrganizationName($row['orgId']),
              'name'          => $row['name'],
              'blurb'			    => html_entity_decode(strip_tags(substr($row['description'],0,100)).'...', ENT_QUOTES, 'UTF-8'),
              'description'   => $row['description'],
              'meetings'      => $this->getMeetingsForEvent($row['eventId'], $registrantId),
              'attendeeTotal' => $this->getAttendeeTotal($row['eventId']),
              'isRegistered'  => $this->isRegisteredForEvent($row['eventId'], $registrantId),
              'isCheckedIn'   => $this->isCheckedInForEvent($row['eventId'], $registrantId)
            );
        }
      }

      return $response;

    }

    public function whoIsRegisteredForEvent($eventId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $response = array();
      $stmt = $this->conn->prepare("SELECT * FROM attendees WHERE eventId = :eventId");
      $stmt->bindParam(':eventId', $eventId);

      if ($stmt->execute()) {
        $registrants = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($registrants AS $row) {

          $response [] = array (
              'attendeeId'      => $row['attendeeId'],
              'fullName'        => $this->getFullName($row['registrantId']),
              'meetingId'       => $row['meetingId'],
              'location'        => $row['location'],
              'checkedIn'       => $row['checkedIn'] == '1',
              'checkedInDate'   => $row['checkedInDate'] ? date('m/d/Y h:i a', strtotime($row['checkedInDate'])) : '',
              'meetings'        => $this->getMeetingsForEvent($row['eventId'], $row['registrantId']),
            );
        }
      }

      return $response;

    }

    public function getAllEventsForAdmin($orgId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d');
      $response = array ();

      $stmt = $this->conn->prepare("SELECT * FROM events WHERE orgId = :orgId ORDER BY startDate ASC");
      $stmt->bindParam(':orgId', $orgId);

      if ($stmt->execute()) {
        $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($events AS $row) {

          $response [] = array (
              'eventId'         => $row['eventId'],
              'startDate'       => date('m/d/Y',strtotime($row['startDate'])),
              'endDate'         => date('m/d/Y',strtotime($row['endDate'])),
              'location'        => $row['location'],
              'orgId'           => $row['orgId'],
              'orgName'         => $this->getOrganizationName($row['orgId']),
              'name'            => $row['name'],
              'blurb'			      => html_entity_decode(strip_tags(substr($row['description'],0,100)).'...', ENT_QUOTES, 'UTF-8'),
              'description'     => $row['description'],
              'meetings'        => $this->getMeetingsForEvent($row['eventId'], $registrantId),
              'attendeeTotal'   => $this->getAttendeeTotal($row['eventId']),
              'whoIsRegistered' => $this->whoIsRegisteredForEvent($row['eventId']),
            );
        }
      }

      return $response;

    }

    public function getAllMyEvents($registrantId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d');
      $response = array ();

      $stmt = $this->conn->prepare("SELECT e.*, a.checkedIn, a.checkedInDate FROM events e LEFT JOIN attendees a ON e.eventId = a.eventId WHERE e.endDate >= :endDate AND a.registrantId = :registrantId ORDER BY e.startDate ASC");
      $stmt->bindParam(':endDate', $now);
      $stmt->bindParam(':registrantId', $registrantId);

      if ($stmt->execute()) {
        $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($events AS $row) {

          $response [] = array (
              'eventId'       => $row['eventId'],
              'registrantId'  => $registrantId,
              'startDate'     => date('m/d/Y',strtotime($row['startDate'])),
              'endDate'       => date('m/d/Y',strtotime($row['endDate'])),
              'location'      => $row['location'],
              'orgId'         => $row['orgId'],
              'orgName'       => $this->getOrganizationName($row['orgId']),
              'name'          => $row['name'],
              'blurb'			    => html_entity_decode(strip_tags(substr($row['description'],0,100)).'...', ENT_QUOTES, 'UTF-8'),
              'description'   => $row['description'],
              'meetings'      => $this->getMeetingsForEvent($row['eventId'], $registrantId),
              'attendeeTotal' => $this->getAttendeeTotal($row['eventId']),
              'isCheckedIn'   => $row['checkedIn'] == 1,
              'checkedInDate' => $row['checkedIn'] == 1 ? date('m/d/Y h:i a', strtotime($row['checkedInDate'])) : ''
            );
        }
      }

      return $response;

    }

    private function isRegisteredForEvent($eventId, $registrantId) {
      $stmt = $this->conn->prepare("SELECT COUNT(*) AS total FROM attendees WHERE eventId = :eventId AND registrantId = :registrantId AND meetingId = '0'");
      $stmt->bindParam(':eventId', $eventId);
      $stmt->bindParam(':registrantId', $registrantId);
      $post_data = array();
      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return $row['total'] > 0;
      } else {
        return false;
      }
    }

    private function isRegisteredForMeeting($meetingId, $registrantId) {
      $stmt = $this->conn->prepare('SELECT COUNT(*) AS total FROM attendees WHERE meetingId = :meetingId AND registrantId = :registrantId');
      $stmt->bindParam(':meetingId', $meetingId);
      $stmt->bindParam(':registrantId', $registrantId);
      $post_data = array();
      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return $row['total'] > 0;
      } else {
        return false;
      }
    }

    private function isCheckedInForEvent($eventId, $registrantId) {
      $stmt = $this->conn->prepare("SELECT COUNT(*) AS total FROM attendees WHERE eventId = :eventId AND registrantId = :registrantId AND meetingId = '0' AND checkedIn = '1'");
      $stmt->bindParam(':eventId', $eventId);
      $stmt->bindParam(':registrantId', $registrantId);
      $post_data = array();
      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return $row['total'] > 0;
      } else {
        return false;
      }
    }

    private function isCheckedInForMeeting($meetingId, $registrantId) {
      $stmt = $this->conn->prepare("SELECT COUNT(*) AS total FROM attendees WHERE meetingId = :meetingId AND registrantId = :registrantId AND checkedIn ='1'");
      $stmt->bindParam(':meetingId', $meetingId);
      $stmt->bindParam(':registrantId', $registrantId);
      $post_data = array();
      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return $row['total'] > 0;
      } else {
        return false;
      }
    }

    public function checkInToEvent($eventId, $registrantId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d H:i:s');
      if ($this->isRegisteredForEvent($eventId, $registrantId)) {
        $sql = "UPDATE attendees SET checkedIn = '1', checkedInDate = :checkedInDate, dateModified = :dateModified WHERE eventId = :eventId AND registrantId = :registrantId AND meetingId = '0'";
        $stmt = $this->conn->prepare($sql);
        $stmt->bindParam(':checkedInDate', $now);
        $stmt->bindParam(':dateModified', $now);
        $stmt->bindParam(':eventId', $eventId);
        $stmt->bindParam(':registrantId', $registrantId);
        if ($stmt->execute()) {
          return true;
        } else {
          return false;
        }
      } else {
        return false;
      }
    }

    public function checkInToMeeting($meetingId, $registrantId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d H:i:s');
      if ($this->isRegisteredForMeeting($meetingId, $registrantId)) {
        $sql = "UPDATE attendees SET checkedIn = '1', checkedInDate = :checkedInDate, dateModified = :dateModified WHERE meetingId = :meetingId AND registrantId = :registrantId";
        $stmt = $this->conn->prepare($sql);
        $stmt->bindParam(':checkedInDate', $now);
        $stmt->bindParam(':dateModified', $now);
        $stmt->bindParam(':meetingId', $meetingId);
        $stmt->bindParam(':registrantId', $registrantId);
        if ($stmt->execute()) {
          return true;
        } else {
          return false;
        }
      } else {
        return true;
      }
    }

    private function getOrgIdForEvent($eventId) {
      $stmt = $this->conn->prepare('SELECT orgId FROM events WHERE eventId = :eventId');
      $stmt->bindParam(':eventId', $eventId);
      if ($stmt->execute()) {
      $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return !empty($row['orgId']) ? $row['orgId'] : '0';
      } else {
        return '0';
      }
    }

    public function registerForEvent($eventId, $registrantId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d H:i:s');
      if (!$this->isRegisteredForEvent($eventId, $registrantId)) {
        $orgId = $this->getOrgIdForEvent($eventId);
        $sql = "INSERT INTO attendees SET registrantId = :registrantId, eventId = :eventId, orgId = :orgId, meetingId = '0', dateAdded = :dateAdded, dateModified = :dateModified";
        $stmt = $this->conn->prepare($sql);
        $stmt->bindParam(':dateAdded', $now);
        $stmt->bindParam(':dateModified', $now);
        $stmt->bindParam(':eventId', $eventId);
        $stmt->bindParam(':orgId', $orgId);
        $stmt->bindParam(':registrantId', $registrantId);
        if ($stmt->execute()) {
          return true;
        } else {
          return false;
        }
      } else {
        return true;
      }
    }

    public function registerForMeeting($meetingId, $registrantId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d H:i:s');
      if (!$this->isRegisteredForMeeting($meetingId, $registrantId)) {
        $sql = "INSERT INTO attendees SET registrantId = :registrantId, meetingId = :meetingId, dateAdded = :dateAdded, dateModified = :dateModified";
        $stmt = $this->conn->prepare($sql);
        $stmt->bindParam(':dateAdded', $now);
        $stmt->bindParam(':dateModified', $now);
        $stmt->bindParam(':meetingId', $meetingId);
        $stmt->bindParam(':registrantId', $registrantId);
        if ($stmt->execute()) {
          return true;
        } else {
          return false;
        }
      } else {
        return false;
      }
    }

    private function getAttendeeTotal($eventId) {
      $stmt     = $this->conn->prepare('SELECT COUNT(*) AS total FROM attendees WHERE eventId = :eventId');
      $stmt->bindParam(':eventId', $eventId);
      $post_data = array();
      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return (int)$row['total'];
      } else {
        return 0;
      }
    }



  public function updateUserPreferences($username, $preferences) {
    date_default_timezone_set($_ENV['TIMEZONE']);

    $settings = '';
    $updates = array();

    if (!empty($preferences) && is_array($preferences)) {
      foreach ($preferences as $key => $value) {
        $updates[$key] = ($value) ? 'yes' : 'no';
      }

      $settings = serialize($updates);
    }

    $stmt = $this->conn->prepare('UPDATE user_preference SET settings = :settings, dateModified = NOW() WHERE username = :username ');
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

	public function forgotPassword($username) {
    date_default_timezone_set($_ENV['TIMEZONE']);
      	$stmt = $this->conn->prepare('SELECT username, email, mobilephone FROM registrants WHERE username = :username');

        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();

        if (isset($row) && $row) {
          	// Found registrant with the username
          	// Generate new reset code
          	$email		         = $row['email'];
          	$mobilephone       = $row['mobilephone'];

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
	     	    $message 	= '<p>Someone just requested that the password be reset for your account at '.$from_name.'.</p><p>If this was a mistake, just ignore this email and nothing will happen.</p><p>To reset your password, click the following link:</p>
	   <p><a href="'.$from_url.'reset?c='.$reset_code.'">Reset My Password</a></p>';

            if ($mobilephone) {
              $this->sendSMS($mobilephone, 'Reset code is: '.$reset_code_short);
              return 'mobile';
            } else if ($email) {
              $this->sendEmail($username, $email, $subject, $message, 0);
              return 'email';
            } else {
              return false;
            }

        } else {
            // registrant not existed with the email
            return 'not_username';
        }
   }

   public function forgotAdminPassword($username) {
     date_default_timezone_set($_ENV['TIMEZONE']);
       	$stmt = $this->conn->prepare('SELECT username, email, mobilephone FROM admins WHERE username = :username');

         $stmt->bindParam(':username', $username);
         $stmt->execute();
         $stmt->setFetchMode(PDO::FETCH_ASSOC);
         $row = $stmt->fetch();

         if (isset($row) && $row) {
           $email		         = $row['email'];
           $mobilephone       = $row['mobilephone'];

           $reset_code_short  = mt_rand(100000,999999);
           $reset_code = sha1(uniqid(rand(), true));
           date_default_timezone_set($_ENV['TIMEZONE']);
           $reset_dt = date('Y-m-d H:i:s');
           $reset_code_active = 1;

           $stmt = $this->conn->prepare('UPDATE admins SET reset_code = :reset_code, reset_code_short = :reset_code_short, reset_code_active = :reset_code_active, reset_dt = :reset_dt, dateModified = NOW() WHERE username = :username');
           $stmt->bindParam(':username',$username);
           $stmt->bindParam(':reset_code',$reset_code);
           $stmt->bindParam(':reset_code_short',$reset_code_short);
           $stmt->bindParam(':reset_code_active',$reset_code_active);
           $stmt->bindParam(':reset_dt',$reset_dt);
           $stmt->execute();

           $from_name 	= $this->getSetting('config_name');
           $from_url	= $_ENV['HTTP_CATALOG'];
 	     	   $subject 	= 'Password Reset';
 	     	   $message 	= '<p>Someone just requested that the password be reset for your account at '.$from_name.'.</p><p>If this was a mistake, just ignore this email and nothing will happen.</p><p>To reset your password, click the following link:</p>
 	   <p><a href="'.$from_url.'reset?c='.$reset_code.'">Reset My Password</a></p>';

           if ($mobilephone) {
             $this->sendSMS($mobilephone, 'Reset code is: '.$reset_code_short);
             return 'mobile';
           } else if ($email) {
             $this->sendEmail($username, $email, $subject, $message, 0);
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

   private function getAdminUsernameFromResetCode($reset_code) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $sql = "SELECT username FROM admins WHERE (reset_code = :reset_code OR reset_code_short = :reset_code) AND reset_code_active = '1' AND reset_dt >= DATE_SUB(NOW(), INTERVAL 30 MINUTE)";
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

  public function resetPassword($reset_code, $password) {
    date_default_timezone_set($_ENV['TIMEZONE']);

    $username = $this->getUsernameFromResetCode($reset_code);

    if ($username) {
      $password_hash = password_hash($password, PASSWORD_DEFAULT);

      $stmt = $this->conn->prepare("UPDATE registrants SET password = :password, reset_code = '', reset_code_short = '', reset_code_active = '0', dateModified = NOW() WHERE username = :username");

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

  public function resetAdminPassword($reset_code, $password) {
    date_default_timezone_set($_ENV['TIMEZONE']);

    $username = $this->getAdminUsernameFromResetCode($reset_code);

    if ($username) {
      $password_hash = password_hash($password, PASSWORD_DEFAULT);

      $stmt = $this->conn->prepare("UPDATE admins SET password = :password, reset_code = '', reset_code_short = '', reset_code_active = '0', dateModified = NOW() WHERE username = :username");

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

		$fullName		= isset($resident_info['fullName']) ? $resident_info['fullName'] : 'Resident';

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


	    $html .= '<br/><p>Dear '.$fullName.',</p><p>'.html_entity_decode($message, ENT_QUOTES, 'UTF-8').'</p>

	    <br/>
<div class="footer"><hr><i>Copyright &copy; '.date('Y').' '.$from_name. ', All rights reserved.</i><br/><br/>Private and Confidential: This email was sent to '.$fullName.' at '.$email.' who is a registered resident/owner at '.$from_name.'<br/><br/>Our mailing address is:<br/>'.$from_address.'
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


  public function checkLogin($username, $password) {
    $stmt = $this->conn->prepare("SELECT username, password FROM registrants WHERE username = :username");

    $stmt->bindParam(':username', $username);
    $stmt->execute();
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
    $row = $stmt->fetch();

    if (isset($row) && $row) {
        // Found registrant with the username
        // Now verify the password

        if (password_verify($password,$row['password'])) {
            // User password is correct
            return 'valid';
        } else {
            // registrant password is incorrect
            return 'not_password';
        }
    } else {
        // registrant not existed with the email
        return 'not_username';
    }
  }

  private function hasCheckedInForEvent($registrantId, $eventId) {
    $sql = "SELECT COUNT(*) AS total FROM attendees WHERE registrantId = :registrantId AND eventId = :eventId AND meetingId = '0'";
    $stmt = $this->conn->prepare($sql);
    $stmt->bindParam(':registrantId', $registrantId);
    $stmt->bindParam(':eventId', $eventId);

    if ($stmt->execute()) {
      $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return $row['total'] > 0;
    } else {
      return false;
    }
  }

  public function checkinForEventAdmin($registrantId, $eventId) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $now = date('Y-m-d H:i:s');
    if ($this->hasCheckedInForEvent($registrantId, $eventId)) {
      return true;
    }
    $stmt = $this->conn->prepare("UPDATE attendees SET checkedIn = '1', checkedInDate = :now, dateModified = :now WHERE registrantId = :registrantId AND eventId = :eventId AND meetingId = '0'");
    $stmt->bindParam(':now', $now);
    $stmt->bindParam(':registrantId', $registrantId);
    $stmt->bindParam(':eventId', $eventId);
    if ($stmt->execute()) {
      return true;
    } else {
      return false;
    }
  }

  private function hasCheckedInForMeeting($registrantId, $meetingId) {
    $sql = "SELECT COUNT(*) AS total FROM attendees WHERE registrantId = :registrantId AND meetingId = :meetingId";
    $stmt = $this->conn->prepare($sql);
    $stmt->bindParam(':registrantId', $registrantId);
    $stmt->bindParam(':meetingId', $meetingId);

    if ($stmt->execute()) {
      $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return $row['total'] > 0;
    } else {
      return false;
    }
  }

  public function checkinForMeetingAdmin($registrantId, $meetingId) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $now = date('Y-m-d H:i:s');
    if ($this->hasCheckedInForEvent($registrantId, $meetingId)) {
      return true;
    }
    $stmt = $this->conn->prepare("UPDATE attendees SET checkedIn = '1', checkedInDate = :now, dateModified = :now WHERE registrantId = :registrantId AND meetingId = :meetingId");
    $stmt->bindParam(':now', $now);
    $stmt->bindParam(':registrantId', $registrantId);
    $stmt->bindParam(':meetingId', $meetingId);
    if ($stmt->execute()) {
      return true;
    } else {
      return false;
    }
  }

  public function checkAdminLogin($username, $password) {
    $stmt = $this->conn->prepare("SELECT username, password FROM admins WHERE username = :username");

    $stmt->bindParam(':username', $username);
    $stmt->execute();
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
    $row = $stmt->fetch();

    if (isset($row) && $row) {
        // Found registrant with the username
        // Now verify the password

        if (password_verify($password,$row['password'])) {
            // User password is correct
            return 'valid';
        } else {
            // registrant password is incorrect
            return 'not_password';
        }
    } else {
        // registrant not existed with the email
        return 'not_username';
    }
  }


  private function generateUniqueUsername($firstName, $lastName){
    $new_username   = strtolower($firstName.$lastName);
    $count = $this->howManyUsernamesLike($new_username);

    if(!empty($count)) {
        $new_username = $new_username . $count;
    }

    return $new_username;
  }

  public function addUser($firstName, $lastName, $email, $mobilephone, $password) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $now = date('Y-m-d H:i:s');
    $password_hash = password_hash(trim($password), PASSWORD_DEFAULT);
    $username = $this->generateUniqueUsername($firstName, $lastName);
    $fullName = ucwords($firstName)." ".ucwords($lastName);
    $stmt = $this->conn->prepare("INSERT INTO registrants SET firstName = :firstName, lastName = :lastName, fullName = :fullName, email = :email, mobilephone = :mobilephone, dateAdded = :now, dateModified = :now, username = :username, password = :password, profileVisible = '0'");
    $stmt->bindParam(':username', $username);
    $stmt->bindParam(':password', $password_hash);
    $stmt->bindParam(':firstName', $firstName);
    $stmt->bindParam(':lastName', $lastName);
    $stmt->bindParam(':fullName', $fullName);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':mobilephone', $mobilephone);
    $stmt->bindParam(':now', $now);
    if ($stmt->execute()) {
      $profile = $this->getProfileByUsername($username);
      $profile['success'] = true;
      return $profile;
    } else {
      return false;
    }
  }


  public function getProfileByUsername($username) {
      $stmt = $this->conn->prepare('SELECT registrantId, username, fullName, email, mobilephone, profileVisible FROM registrants WHERE username = :username');
      $stmt->bindParam(':username', $username);
      if ($stmt->execute()) {
      	$stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        return $row;
      } else {
          return NULL;
      }
  }

  public function getAdminProfileByUsername($username) {
    $stmt = $this->conn->prepare('SELECT orgId, username, name, company, email, mobilephone FROM admins WHERE username = :username');
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
      $phone = $data['phone'];
      $stmt = $this->conn->prepare('UPDATE registrants SET phone = :phone, dateModified=NOW() WHERE username = :username');
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':phone',$phone);
      $stmt->execute();
    }

    if (!empty($data['mobilephone'])) {
      $stmt = $this->conn->prepare('UPDATE registrants SET mobilephone = :mobilephone, dateModified=NOW() WHERE username = :username');
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':mobilephone',$data['mobilephone']);
      $stmt->execute();
    }

    if (!empty($data['privacy'])) {
      $stmt = $this->conn->prepare('UPDATE registrants SET privacy = :privacy, dateModified=NOW() WHERE username = :username');
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':privacy',$data['privacy']);
      $stmt->execute();
    }

    // add image
    if (!empty($data['images']) && array_key_exists('mime',$data['images']) && array_key_exists('data', $data['images'])) {
      $mime = $data['images']['mime'];
      $data = $data['images']['data'];
      if ($mime && $data) {
        $extension = $this->returnFileExtension($mime);
        $uploadDir  = $_ENV['DIR_PROFILE_IMAGE'];
        $uploadPath = $_ENV['PATH_PROFILE_IMAGE'];
        $img        = str_replace(' ', '+', $data);
        $imgData    = base64_decode($img);
        $filename   = $username . '_' . uniqid() . '.'. $extension;
        $imgPath    = $uploadPath . $filename;
        $file       = $uploadDir . $filename;
        file_put_contents($file, $imgData);
        // update profilepic in wch_user
        $this->updateProfilePhoto($username, $imgPath);

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

  public function getEventsForAttendeeForOrgId($orgId, $registrantId) {
    $sql = "SELECT e.* FROM events e LEFT JOIN attendees a ON e.eventId =  a.eventId WHERE e.orgId = :orgId AND a.registrantId = :registrantId";
    $eventsData = array();
    $stmt = $this->conn->prepare($sql);
    $stmt->bindParam(':orgId', $orgId);
    $stmt->bindParam(':registrantId', $registrantId);
    if ($stmt->execute()) {
      $events = $stmt->fetchAll(PDO::FETCH_ASSOC);

      if ($events) {
        foreach ($events AS $e) {
          $eventsData[] = array (
            'eventId'	  => $e['eventId'],
            'name'      => $e['name'],
            'startDate' => $e['startDate'],
            'endDate'   => $e['endDate'],
            'location'  => $e['location'],
            'city'      => $e['city'],
            'zip'       => $e['zip']
          );
        }
      }
    }

    return $eventsData;
  }

  public function getPeopleForAdmins($orgId = 1, $string = '') {

    if ($string == '') { return array(); }

    $query = '%'. strtolower($string) . '%';
    $peeps = array();
    $stmt = $this->conn->prepare("SELECT r.* FROM attendees a LEFT JOIN events e ON a.eventID = e.eventId LEFT JOIN registrants r ON a.registrantId = r.registrantId WHERE e.orgId = :orgId AND LOWER(r.fullName) LIKE :query");
    $stmt->bindParam(':query', $query);
    $stmt->bindParam(':orgId', $orgId);

    if ($stmt->execute()) {
      $people = $stmt->fetchAll(PDO::FETCH_ASSOC);

      if ($people) {
        foreach ($people AS $p) {
          $peeps[] = array (
            'registrantId'	  => $p['registrantId'],
            'fullName'        => $p['fullName'],
            'email'           => $p['email'],
            'mobilephone'     => $p['mobilephone'],
            'address'         => $p['address']. ' '. $p['city']. ' ' . $p['state'] . ' ' . $p['zip'],
            'eventsData'      => $this->getEventsForAttendeeForOrgId($orgId, $p['registrantId'])
          );
        }
      }
    }

    return $peeps;
  }


		public function sendPushNotificationsToIndividual($username, $message, $data = array(), $sound = 0) {

			// get group members
			$filters = array(
				array(
				"field" =>"tag",
				"key" => "username",
				"relation" => "=",
				"value" => $username
			)
			);

			// create push notification data
			$contents = array(
				"en" => $message,
			);

			$fields = array(
				'app_id'    => $_ENV['ONESIGNAL_APP_ID'],
				'contents'    => $contents,
				'data'    => $data,
				'filters'   => $filters,
				'ios_sound' => $sound ? 'alert.wav' : ''
			);

			$fields = json_encode($fields);
				$ch = curl_init();
				curl_setopt($ch, CURLOPT_URL, $_ENV['ONESIGNAL_API_URL']);
				curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json; charset=utf-8',
														 'Authorization: Basic '.$_ENV['ONESIGNAL_APP_KEY']));
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
				curl_setopt($ch, CURLOPT_HEADER, FALSE);
				curl_setopt($ch, CURLOPT_POST, TRUE);
				curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
				curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);

				$response = curl_exec($ch);
				curl_close($ch);

			return json_decode($response, true);
		}

		public function getGroupName($group_id) {
	   	$stmt = $this->conn->prepare('SELECT name FROM group WHERE group_id = :group_id');

      $stmt->bindParam(':group_id', $group_id);
      $stmt->execute();
      $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();

      if (isset($row) && $row) {
       return $row['name'];
      } else {
       return NULL;
      }
	 }

}

?>
