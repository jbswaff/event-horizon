# Event Horizon - Pi-hole v6 Ad Blocking Control

Event Horizon is a lightweight Pi-hole-companion that allows network users to temporarily disable Pi-hole without a complex UI, presented on a simple web page. 
Event Horizon is a lightweight Pi-hole-companion designed for controlling Pi-hole's ad blocking feature on-demand by non-technical users who do not need or desire access to the Pi-hole admin web UI. It allows network users to disable Pi-hole's ad blocking for a set duration (configured during install or via event-horizon.conf any time after install) through a simple, user-friendly web interface. The service uses the Pi-hole API to interact with one or multiple Pi-hole instances, and it logs each action for transparency and administration ease.

he name Event Horizon was inspired by the concept of a critical boundary in space—once something crosses it, there's no turning back. Much like the event horizon, this service puts control into the hands of users on your network. When the ad blocker is disabled, you cross a threshold into a filterless web experience. Just as space's event horizon signifies a point of no return, disabling your adblocker marks a shift in how you experience the internet.

---

## Features

- **Pi-hole v6 Support**: This service is **compatible with Pi-hole v6**. If you're running Pi-hole v5 or earlier, this service will not work. Support for v5 may be added later, but is not planned at this time.
- **Multiple Pi-hole Support**: You can manage multiple Pi-hole instances from a single Event Horizon server with a single button.
- **Web Interface**: A simple, mobile-friendly interface with a single button to disable Pi-hole's ad blocking for a specified duration (specified in server config).
- **API Integration**: The service interacts directly with Pi-hole's API, no SSH or additional configuration required on Pi-hole.
- **Logs**: Logs are automatically generated each time the ad blocker is disabled, and the logs are accessible through the web interface. You decide whether or not to include a link on the main page for the logs.
- **Customizable Disable Time**: The default duration is 10 minutes, but this can be configured during installation.

---

## Security Warning

> **IMPORTANT**: This service **does not** include any form of authentication or encryption (TLS). You must firewall this service yourself to restrict access from access outside your network.

---

## Installation

To install the Event Horizon server, you can use the following one-line command. It will handle all the necessary steps, including the installation of dependencies and configuring the service.

### Requirements

- **Pi-hole v6**: This service works with Pi-hole v6 only.
- **Python 3.x**: The service is written in Python 3.
- **Internet Access**: To download the required files.

Event Horizon is lightweight by design and can be run alongside Pi-hole, even on a Raspberry Pi. Only one instance of Event Horizon is needed for a group of Pi-holes, as it is able to manage multiple Pi-hole instances.

### Installation Steps

1. **Download the installer**:
   The easiest method is to use `curl` to download and execute the installer:


```
curl -fsSL https://raw.githubusercontent.com/jbswaff/event-horizon/main/install.sh | sudo bash
```


2. **During installation**, you will be prompted to provide the following configuration details:
- The **Pi-hole IP addresses** and **API password** for each Pi-hole instance. It is recommended to use an application password generated from the Pi-hole web UI instead of your top-level password.
- The **duration for disabling ad blocking** (in minutes).
- Whether to **show a link to logs** on the main page.

The installation script will automatically configure the necessary files and services for you. The installer will automatically test API connectivity during the installation process, alerting you to an issue early.

---

## Configuration File

The configuration file is located at `/etc/event-horizon/event-horizon.conf`. It contains all the configuration options for the service, including Pi-hole instances and settings for the disable time and logs visibility.

You can manually edit this file to update settings if needed, but the installation script will handle the configuration by default.

---

## Logs

The logs for each time ad blocking is disabled are stored in `/var/log/event-horizon/requests.log`. You can view the logs directly from the web interface if you enabled the log link during installation. If you chose not to display a link to logs on the main page, you can still access the logs here: http://<Event-Viewer-IP-or-Hostname>:PORT/logs

The logs contain:

- The **IP address** of the user who triggered the action.
- The **Pi-hole instances** affected and their responses.
- The **time** when the action was performed. Be sure to check the time zone of the system running Event Viewer to avoid confusion later.

---

## Service Control

Once installed, the service is automatically started and enabled to run on boot. You can manage the service with the following commands:

- **Start the service**:  
```
sudo systemctl start event-horizon.service
```

- **Stop the service***:
```
sudo systemctl stop event-horizon.service
```

- **Enable the service on boot**:
```
sudo systemctl enable event-horizon.service
```

- **Disable the service on boot**:
```
curl -fsSL https://raw.githubusercontent.com/jbswaff/event-horizon/main/install.sh
 | sudo bash
```

- **Check the status of the service**:
```
sudo systemctl status event-horizon.service
```

- **View logs of the service**:
```
journalctl -u event-horizon.service -n 200 --no-pager
```

- **Uninstallation**:
  To uninstall Event Horizon, run the following commands:
```
sudo systemctl stop event-horizon.service
sudo systemctl disable event-horizon.service
sudo rm -rf /opt/event-horizon /etc/event-horizon /var/log/event-horizon
sudo rm /etc/systemd/system/event-horizon.service
sudo systemctl daemon-reload
```

**Acknowledgments**
Pi-hole v6 for providing an easy-to-use and powerful ad-blocking solution.
The Python community for their continued work on the Python ecosystem.
This project is developed and maintained by Joshua Swafford for the Pi-hole community.
