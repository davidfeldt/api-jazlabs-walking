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

  public function getEventIdForMeeting($meetingId) {
    $stmt = $this->conn->prepare('SELECT eventId FROM meetings WHERE meetingId = :meetingId');
    $stmt->bindParam(':meetingId', $meetingId);
    if ($stmt->execute()) {
      $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return !empty($row['eventId']) ? $row['eventId'] : '0';
    } else {
      return '0';
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

  public function getAdminName($adminId) {
    $stmt = $this->conn->prepare('SELECT name FROM admins WHERE adminId = :adminId');
    $stmt->bindParam(':adminId', $adminId);
    if ($stmt->execute()) {
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
      $row = $stmt->fetch();
      return !empty($row['name']) ? $row['name'] : 'N/A';
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
              'isCheckedIn'   => $this->isCheckedInForMeeting($row['meetingId'], $registrantId),
              'checkedInDate' => $this->checkedInDateForMeeting($row['meetingId'], $registrantId),
              'qrCodeValue'   => '{"registrantId": "'.$registrantId.'", "meetingId": "'.$row['meetingId'].'"}'
            );
        }
      }

      return $response;
    }

    public function getMeetingsForEventAdmin($eventId) {
        $response = array ();

        $stmt = $this->conn->prepare("SELECT * FROM meetings WHERE eventId = :eventId ORDER BY startDate ASC");
        $stmt->bindParam(':eventId', $eventId);

        if ($stmt->execute()) {
          $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
          foreach ($events AS $row) {

            $response [] = array (
                'meetingId'       => $row['meetingId'],
                'eventId'         => $row['eventId'],
                'startDate'       => date('m/d g:i a',strtotime($row['startDate'])),
                'endDate'         => date('m/d g:i a',strtotime($row['endDate'])),
                'location'        => $row['location'],
                'eventName'       => $this->getEventName($row['eventId']),
                'name'            => $row['name'],
                'capacity'        => $row['capacity'],
                'totalRegistered' => $this->totalRegisteredForMeeting($row['meetingId']),
                'totalCheckedIn'  => $this->totalCheckedInForMeeting($row['meetingId']),
              );
          }
        }

        return $response;
      }

      private function totalRegisteredForMeeting($meetingId) {
        $stmt = $this->conn->prepare('SELECT COUNT(*) AS total FROM attendees WHERE meetingId = :meetingId');
        $stmt->bindParam(':meetingId', $meetingId);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return number_format($row['total']);
        } else {
          return false;
        }
      }

      private function totalRegisteredForEvent($eventId) {
        $stmt = $this->conn->prepare("SELECT COUNT(*) AS total FROM attendees WHERE eventId = :eventId AND meetingId = '0'");
        $stmt->bindParam(':eventId', $eventId);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return number_format($row['total']);
        } else {
          return false;
        }
      }

      private function totalCheckedInForMeeting($meetingId) {
        $stmt = $this->conn->prepare("SELECT COUNT(*) AS total FROM attendees WHERE meetingId = :meetingId AND checkedIn = '1'");
        $stmt->bindParam(':meetingId', $meetingId);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return number_format($row['total']);
        } else {
          return false;
        }
      }

      private function totalCheckedInForEvent($eventId) {
        $stmt = $this->conn->prepare("SELECT COUNT(*) AS total FROM attendees WHERE eventId = :eventId AND meetingId = '0' AND checkedIn = '1'");
        $stmt->bindParam(':eventId', $eventId);
        $post_data = array();
        if ($stmt->execute()) {
          $stmt->setFetchMode(PDO::FETCH_ASSOC);
          $row = $stmt->fetch();
          return number_format($row['total']);
        } else {
          return false;
        }
      }

    public function getEvent($registrantId, $eventId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d');
      $response = array ();

      $stmt = $this->conn->prepare("SELECT * FROM events WHERE eventId = :eventId");
      $stmt->bindParam(':eventId', $eventId);

      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();

        $response  = array (
            'eventId'       => $row['eventId'],
            'registrantId'  => $registrantId,
            'startDate'     => date('m/d/Y',strtotime($row['startDate'])),
            'endDate'       => date('m/d/Y',strtotime($row['endDate'])),
            'avatar'        => !empty($row['avatar']) ? 'https://spectacularapps.us/img/organizations/'.$row['avatar'] : 'https://jazlabs.com/img/logo_light.png',
            'image'         => !empty($row['image']) ? 'https://spectacularapps.us/img/events/'.$row['image'] : '',
            'location'      => $row['location'],
            'city'          => $row['city'],
            'state'         => $row['state'],
            'zip'           => $row['zip'],
            'orgId'         => $row['orgId'],
            'orgName'       => $this->getOrganizationName($row['orgId']),
            'name'          => $row['name'],
            'blurb'			    => $row['description'] ? html_entity_decode(strip_tags(substr($row['description'],0,100)).'...', ENT_QUOTES, 'UTF-8') : '',
            'description'   => $row['description'],
            'meetings'      => $this->getMeetingsForEvent($row['eventId'], $registrantId),
            'attendeeTotal' => $this->getAttendeeTotal($row['eventId']),
            'isRegistered'  => $this->isRegisteredForEvent($row['eventId'], $registrantId),
            'isCheckedIn'   => $this->isCheckedInForEvent($row['eventId'], $registrantId)
          );
      }

      return $response;
    }

    public function getAllEvents($registrantId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d');
      $response = array ();

      $stmt = $this->conn->prepare("SELECT * FROM events WHERE endDate >= :endDate ORDER BY startDate ASC");
      $stmt->bindParam(':endDate', $now);

      if ($stmt->execute()) {
        $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($events AS $row) {

          $response [] = array (
              'eventId'       => $row['eventId'],
              'registrantId'  => $registrantId,
              'startDate'     => date('m/d/Y',strtotime($row['startDate'])),
              'endDate'       => date('m/d/Y',strtotime($row['endDate'])),
              'avatar'        => !empty($row['avatar']) ? 'https://spectacularapps.us/img/organizations/'.$row['avatar'] : 'https://jazlabs.com/img/logo_light.png',
              'image'         => !empty($row['image']) ? 'https://spectacularapps.us/img/events/'.$row['image'] : '',
              'location'      => $row['location'],
              'city'          => $row['city'],
              'state'         => $row['state'],
              'zip'           => $row['zip'],
              'orgId'         => $row['orgId'],
              'orgName'       => $this->getOrganizationName($row['orgId']),
              'name'          => $row['name'],
              'blurb'			    => $row['description'] ? html_entity_decode(strip_tags(substr($row['description'],0,100)).'...', ENT_QUOTES, 'UTF-8') : '',
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
      $stmt = $this->conn->prepare("SELECT * FROM attendees WHERE eventId = :eventId AND meetingId = '0'");
      $stmt->bindParam(':eventId', $eventId);

      if ($stmt->execute()) {
        $registrants = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($registrants AS $row) {

          $response [] = array (
              'attendeeId'      => $row['attendeeId'],
              'fullName'        => $this->getFullName($row['registrantId']),
              'meetingId'       => $row['meetingId'],
              'checkedIn'       => $row['checkedIn'] == '1',
              'checkedInDate'   => $row['checkedInDate'] ? date('m/d/Y h:i a', strtotime($row['checkedInDate'])) : ''
              // 'meetings'        => $this->getMeetingsForEvent($row['eventId'], $row['registrantId']),
            );
        }
      }

      return $response;

    }

    public function whoIsCheckedInForEvent($eventId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $response = array();
      $stmt = $this->conn->prepare("SELECT * FROM attendees WHERE eventId = :eventId AND meetingId = '0' AND checkedIn = '1'");
      $stmt->bindParam(':eventId', $eventId);

      if ($stmt->execute()) {
        $registrants = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($registrants AS $row) {

          $response [] = array (
              'attendeeId'      => $row['attendeeId'],
              'fullName'        => $this->getFullName($row['registrantId']),
              'meetingId'       => $row['meetingId'],
              'checkedIn'       => $row['checkedIn'] == '1',
              'checkedInDate'   => $row['checkedInDate'] ? date('m/d/Y h:i a', strtotime($row['checkedInDate'])) : ''
              // 'meetings'        => $this->getMeetingsForEvent($row['eventId'], $row['registrantId']),
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
              'avatar'          => !empty($row['avatar']) ? 'https://spectacularapps.us/img/organizations/'.$row['avatar'] : 'https://jazlabs.com/img/logo_light.png',
              'image'           => !empty($row['image']) ? 'https://spectacularapps.us/img/events/'.$row['image'] : '',
              'location'        => $row['location'],
              'city'            => $row['city'],
              'state'           => $row['state'],
              'zip'             => $row['zip'],
              'orgId'           => $row['orgId'],
              'orgName'         => $this->getOrganizationName($row['orgId']),
              'name'            => $row['name'],
              'blurb'			      => $row['description'] ? html_entity_decode(strip_tags(substr($row['description'],0,100)).'...', ENT_QUOTES, 'UTF-8') : '',
              'description'     => $row['description'],
              'meetings'        => $this->getMeetingsForEventAdmin($row['eventId']),
              'attendeeTotal'   => $this->getAttendeeTotal($row['eventId']),
              'whoIsRegistered' => $this->whoIsRegisteredForEvent($row['eventId']),
              'whoIsCheckedIn'  => $this->whoIsCheckedInForEvent($row['eventId']),
              'totalRegistered' => $this->totalRegisteredForEvent($row['eventId']),
              'totalCheckedIn'  => $this->totalCheckedInForEvent($row['eventId']),
            );
        }
      }

      return $response;

    }

    public function getAllMyEvents($registrantId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d');
      $response = array ();

      $stmt = $this->conn->prepare("SELECT e.*, a.checkedIn, a.checkedInDate FROM events e LEFT JOIN attendees a ON e.eventId = a.eventId WHERE e.endDate >= :endDate AND a.registrantId = :registrantId AND a.meetingId = '0' ORDER BY e.startDate ASC");
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
              'avatar'        => !empty($row['avatar']) ? 'https://spectacularapps.us/img/organizations/'.$row['avatar'] : 'https://jazlabs.com/img/logo_light.png',
              'image'         => !empty($row['image']) ? 'https://spectacularapps.us/img/events/'.$row['image'] : '',
              'location'      => $row['location'],
              'city'          => $row['city'],
              'state'         => $row['state'],
              'zip'           => $row['zip'],
              'orgId'         => $row['orgId'],
              'orgName'       => $this->getOrganizationName($row['orgId']),
              'name'          => $row['name'],
              'blurb'			    => $row['description'] ? html_entity_decode(strip_tags(substr($row['description'],0,100)).'...', ENT_QUOTES, 'UTF-8') : '',
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

    private function checkedInDateForMeeting($meetingId, $registrantId) {
      $stmt = $this->conn->prepare("SELECT checkedInDate FROM attendees WHERE meetingId = :meetingId AND registrantId = :registrantId AND checkedIn ='1'");
      $stmt->bindParam(':meetingId', $meetingId);
      $stmt->bindParam(':registrantId', $registrantId);
      $post_data = array();
      if ($stmt->execute()) {
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $row = $stmt->fetch();
        if (!empty($row['checkedInDate'])) {
          return date('m/d/Y h:i a', strtotime($row['checkedInDate']));
        } else {
          return '';
        }
      } else {
        return '';
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

    public function registerForEvent($registrantId, $eventId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d H:i:s');
      if (!$this->isRegisteredForEvent($eventId, $registrantId)) {
        $orgId = $this->getOrgIdForEvent($eventId);
        $sql = "INSERT INTO attendees SET registrantId = :registrantId, eventId = :eventId, orgId = :orgId, meetingId = '0', checkedIn = '0', dateAdded = :dateAdded, dateModified = :dateModified";
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
        $eventId = $this->getEventIdForMeeting($meetingId);
        $orgId = $this->getOrgIdForEvent($eventId);
        $sql = "INSERT INTO attendees SET orgId = :orgId, registrantId = :registrantId, meetingId = :meetingId, dateAdded = :dateAdded, dateModified = :dateModified";
        $stmt = $this->conn->prepare($sql);
        $stmt->bindParam(':dateAdded', $now);
        $stmt->bindParam(':dateModified', $now);
        $stmt->bindParam(':orgId', $orgId);
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
      $stmt     = $this->conn->prepare("SELECT COUNT(*) AS total FROM attendees WHERE eventId = :eventId AND meetingId = '0'");
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

    public function getMyAnnouncements($registrantId, $page = 1) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $now = date('Y-m-d');
      $response = array ();

      $limit = $_ENV['ANNOUNCEMENTS_LIMIT'];
      $page = (isset($page)) ? $page : 1;
      $start = ($page - 1) * $limit;

      $stmt = $this->conn->prepare("SELECT * FROM announcements WHERE registrantId = :registrantId ORDER BY dateAdded DESC LIMIT $start, $limit");
      $stmt->bindParam(':registrantId', $registrantId);

      if ($stmt->execute()) {
        $announcements = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($announcements AS $row) {

          $response [] = array (
              'id'            => $row['id'],
              'registrantId'  => $registrantId,
              'sentByName'    => $this->getAdminName($row['adminId']),
              'sentByOrg'     => $this->getOrganizationName($row['orgId']),
              'subject'       => $row['subject'],
              'message'       => $row['message'],
              'orgId'         => $row['orgId'],
              'blurb'			    => $row['message'] ? html_entity_decode(strip_tags(substr($row['message'],0,100)).'...', ENT_QUOTES, 'UTF-8') : '',
              'dateAdded'     => date('m/d/Y h:i a', strtotime($row['dateAdded']))
            );
        }
      }

      return $response;

    }

    public function numberOfAnnouncements($registrantId) {
      $stmt     = $this->conn->prepare('SELECT COUNT(*) AS total FROM announcements WHERE registrantId = :registrantId');
      $stmt->bindParam(':registrantId', $registrantId);
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
    $sql = "SELECT COUNT(*) AS total FROM attendees WHERE registrantId = :registrantId AND eventId = :eventId AND meetingId = '0' AND checkedIn = '1'";
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
    $sql = "SELECT COUNT(*) AS total FROM attendees WHERE registrantId = :registrantId AND meetingId = :meetingId AND checkedIn = '1'";
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

  private function hasRegisteredForMeeting($registrantId, $meetingId) {
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
    if ($this->hasCheckedInForMeeting($registrantId, $meetingId)) {
      return true;
    }
    if ($this->hasRegisteredForMeeting($registrantId, $meetingId)) {
      $stmt = $this->conn->prepare("UPDATE attendees SET checkedIn = '1', checkedInDate = :now, dateModified = :now WHERE registrantId = :registrantId AND meetingId = :meetingId");
      $stmt->bindParam(':now', $now);
      $stmt->bindParam(':registrantId', $registrantId);
      $stmt->bindParam(':meetingId', $meetingId);
      if ($stmt->execute()) {
        return true;
      } else {
        return false;
      }
    } else {
      // need to register first before checking in to meeting
      $eventId = $this->getEventIdForMeeting($meetingId);
      $orgId = $this->getOrgIdForEvent($eventId);
      $stmt = $this->conn->prepare("INSERT INTO attendees SET dateAdded = :now, dateModified = :now, orgId = :orgId, registrantId = :registrantId, eventId = :eventId, meetingId = :meetingId");
      $stmt->bindParam(':now', $now);
      $stmt->bindParam(':orgId', $orgId);
      $stmt->bindParam(':registrantId', $registrantId);
      $stmt->bindParam(':eventId', $eventId);
      $stmt->bindParam(':meetingId', $meetingId);
      $stmt->execute();
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

  public function addUser($data) {
    date_default_timezone_set($_ENV['TIMEZONE']);
    $now = date('Y-m-d H:i:s');
    $firstName = !empty($data['firstName']) ? ucwords($data['firstName']) : '';
		$lastName = !empty($data['lastName']) ? ucwords($data['lastName']) : '';
		$email = !empty($data['email']) ? strtolower(trim($data['email'])) : '';
		$title = !empty($data['title']) ? ucwords(trim($data['title'])) : '';
		$company = !empty($data['company']) ? ucwords(trim($data['company'])) : '';
		$mobilephone = !empty($data['mobilephone']) ? $this->formatPhoneNumber($data['mobilephone']) : '';
		$password = !empty($data['password']) ? $data['password'] : '';
    $password_hash = password_hash(trim($password), PASSWORD_DEFAULT);
    $username = $this->generateUniqueUsername($firstName, $lastName);
    $fullName = ucwords($firstName)." ".ucwords($lastName);
    $stmt = $this->conn->prepare("INSERT INTO registrants SET firstName = :firstName, lastName = :lastName, fullName = :fullName, email = :email, phone = '', profileVisible = '', messaging = 'none', pushNotifications = '0', mobilephone = :mobilephone, title = :title, company = :company, dateAdded = :now, dateModified = :now, username = :username, password = :password");
    $stmt->bindParam(':username', $username);
    $stmt->bindParam(':password', $password_hash);
    $stmt->bindParam(':firstName', $firstName);
    $stmt->bindParam(':lastName', $lastName);
    $stmt->bindParam(':fullName', $fullName);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':mobilephone', $mobilephone);
    $stmt->bindParam(':title', $title);
    $stmt->bindParam(':company', $company);
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
      $stmt = $this->conn->prepare('SELECT registrantId, username, firstName, lastName, fullName, email, phone, mobilephone, title, company, profileVisible, messaging, pushNotifications FROM registrants WHERE username = :username');
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
      $stmt = $this->conn->prepare('UPDATE registrants SET pushNotifications = :pushNotifications, dateModified=NOW() WHERE username = :username');
      $stmt->bindParam(':username',$username);
      $stmt->bindParam(':pushNotifications',$data['pushNotifications']);
      $stmt->execute();
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

  public function getCalendarMarkedDatesAdmin($startDate, $endDate, $orgId = 0)  {
    $dates_data  = array();
    date_default_timezone_set($_ENV['TIMEZONE']);
    $startDate = date('Y-m-d', strtotime($startDate));
    $endDate = date('Y-m-d', strtotime($endDate));
    $today = date('Y-m-d');

    $stmt = $this->conn->prepare("SELECT startDate, endDate FROM events WHERE DATE(startDate) >= :startDate AND DATE(endDate) <= :endDate AND orgId = :orgId ORDER BY startDate ASC");
    $stmt->bindParam(':startDate', $startDate);
    $stmt->bindParam(':endDate', $endDate);
    $stmt->bindParam(':orgId', $orgId);

    if ($stmt->execute()) {
      $dates = $stmt->fetchAll(PDO::FETCH_ASSOC);

      if ($dates) {
        foreach ($dates AS $date) {
            $start_date = date('Y-m-d', strtotime($date['startDate']));
            $end_date = date('Y-m-d', strtotime($date['endDate']));
            if ($start_date == $end_date) {
              $dates_data[$start_date] = array(
                'marked'    => true,
                'dotColor'  => 'green',
                'selected'  => $today == $start_date,
              );
            } else {
              $dates_data[$start_date] = array (
                'startingDay'  => true,
                'selected'     => $today == $start_date,
                'color'        => 'green',
                'textColor' => 'white'
              );
              $dates_data[$end_date] = array (
                'selected'  => $today == $end_date,
                'endingDay' => true,
                'color'     => 'green',
                'textColor' => 'white'
              );
            }
        }
      }
    }
    return $dates_data;
  }

  public function deleteEventForAdmin($orgId, $eventId) {
      $stmt = $this->conn->prepare("DELETE FROM events WHERE eventId = :eventId AND orgId = :orgId");
      $stmt->bindParam(':eventId', $eventId);
      $stmt->bindParam(':orgId', $orgId);
      if ($stmt->execute()) {
        return true;
      } else {
        return false;
      }
    }

    private function guidv4($data = null) {
      $data = $data ?? random_bytes(16);

      $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
      $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

      return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    private function getMeetingsByDay($day, $eventId) {
      date_default_timezone_set($_ENV['TIMEZONE']);
      $day = date('Y-m-d', strtotime($day));
      $meetingData = array();
      $stmt = $this->conn->prepare("SELECT * FROM meetings WHERE DATE(startDate) <= :day AND DATE(endDate) >= :day AND eventId = :eventId ORDER BY startDate ASC");
      $stmt->bindParam(':day', $day);
      $stmt->bindParam(':eventId', $eventId);
      if ($stmt->execute()) {
        $meetings = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($meetings AS $meet) {
          $times = $meet['startDate'] == $meet['endDate'] ? date('m/d',strtotime($meet['startDate'])) : date('m/d',strtotime($meet['startDate']))." - ".date('m/d',strtotime($meet['endDate']));
          $meetingData[] = array (
            'name'		    => $meet['name'],
            'times'		    => $times,
            'height'	    => 50,
            'meetingId'		=> $meet['meetingId']
          );
        }
      }
      return $meetingData;
    }

    public function getEventsAndMeetingsByDay($day, $orgId) {
   		date_default_timezone_set($_ENV['TIMEZONE']);
      $day = date('Y-m-d', strtotime($day));
   		$eventData = array();
   		$stmt = $this->conn->prepare("SELECT * FROM events WHERE DATE(startDate) <= :day AND DATE(endDate) >= :day AND orgId = :orgId ORDER BY startDate ASC");
  		$stmt->bindParam(':day', $day);
  		$stmt->bindParam(':orgId', $orgId);
  		if ($stmt->execute()) {
  			$events = $stmt->fetchAll(PDO::FETCH_ASSOC);
  			foreach ($events AS $event) {
  				$times = $event['startDate'] == $event['endDate'] ? date('m/d',strtotime($event['startDate'])) : date('m/d',strtotime($event['startDate']))." - ".date('m/d',strtotime($event['endDate']));
  				$eventData['events'][] = array (
  					'name'		    => $event['name'],
            'eventId'     => $event['eventId'],
  					'times'		    => $times,
  					'height'	    => 50,
  					'meetingId'		=> 0
  				);
          $eventData['meetings'] = $this->getMeetingsByDay($day, $event['eventId']);

  			}
  		}

  		return $eventData;
   	}


   	public function addNewEvent($orgId, $data) {
   		date_default_timezone_set($_ENV['TIMEZONE']);

   		$name = array_key_exists('name', $data) ? trim(ucwords($data['name'])) : '';

   		$startDate = date('Y-m-d', strtotime($data['startDate']));
   		$endDate = date('Y-m-d', strtotime($data['endDate']));

      $description = array_key_exists('description', $data) ? $data['description'] : '';
      $location = array_key_exists('location', $data) ? trim(ucwords($data['location'])) : '';
      $city = array_key_exists('city', $data) ? trim(ucwords($data['city'])) : '';
      $state = array_key_exists('state', $data) ? trim(ucwords($data['state'])) : '';
      $zip = array_key_exists('zip', $data) ? trim(ucwords($data['zip'])) : '';
      $eventCode = $this->guidv4();

      $stmt = $this->conn->prepare("INSERT INTO events SET orgId = :orgId, name = :name, description = :description, startDate = :startDate, endDate = :endDate, location = :location, city = :city, state = :state, zip = :zip, eventCode = :eventCode");
      $stmt->bindParam(':orgId', $orgId);
      $stmt->bindParam(':name', $name);
    	$stmt->bindParam(':description', $description);
    	$stmt->bindParam(':startDate', $startDate);
    	$stmt->bindParam(':endDate', $endDate);
      $stmt->bindParam(':location', $location);
    	$stmt->bindParam(':city', $city);
    	$stmt->bindParam(':state', $state);
    	$stmt->bindParam(':zip', $zip);
    	$stmt->bindParam(':eventCode', $eventCode);

    	return $stmt->execute();

   	}

    public function editEvent($data) {
   		date_default_timezone_set($_ENV['TIMEZONE']);

      $name = array_key_exists('name', $data) ? $data['name'] : '';

   		$startDate = date('Y-m-d', strtotime($data['startDate']));
   		$endDate = date('Y-m-d', strtotime($data['endDate']));

      $description = array_key_exists('description', $data) ? $data['description'] : '';
      $location = array_key_exists('description', $data) ? $data['description'] : '';
      $city = array_key_exists('city', $data) ? $data['city'] : '';
      $state = array_key_exists('state', $data) ? $data['state'] : '';
      $zip = array_key_exists('zip', $data) ? $data['zip'] : '';

   		$stmt = $this->conn->prepare("UPDATE events SET name = :name, description = :description, startDate = :startDate, endDate = :endDate, location = :location, city = :city, state = :state, zip = :zip WHERE eventId = :eventId");
      $stmt->bindParam(':name', $name);
    	$stmt->bindParam(':description', $description);
    	$stmt->bindParam(':startDate', $startDate);
    	$stmt->bindParam(':endDate', $endDate);
      $stmt->bindParam(':location', $location);
    	$stmt->bindParam(':city', $city);
    	$stmt->bindParam(':state', $state);
    	$stmt->bindParam(':zip', $zip);
    	$stmt->bindParam(':eventId', $eventId);

    	return $stmt->execute();

   	}

  public function getEventsForAttendeeForOrgId($orgId, $registrantId) {
    $sql = "SELECT e.* FROM events e LEFT JOIN attendees a ON e.eventId =  a.eventId WHERE e.orgId = :orgId AND a.registrantId = :registrantId AND a.meetingId = '0'";
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
            'startDate' => date('m/d/Y', strtotime($e['startDate'])),
            'endDate'   => date('m/d/Y', strtotime($e['endDate'])),
            'location'  => $e['location'],
            'city'      => $e['city'],
            'state'     => $e['state'],
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
    $stmt = $this->conn->prepare("SELECT DISTINCT r.* FROM attendees a LEFT JOIN events e ON a.eventID = e.eventId LEFT JOIN registrants r ON a.registrantId = r.registrantId WHERE a.meetingId = '0' AND e.orgId = :orgId AND LOWER(r.fullName) LIKE :query");
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
