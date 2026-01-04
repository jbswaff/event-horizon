Current release: v0.2.0-beta.1

# Event Horizon - Pi-hole v6 Ad Blocking Control

Event Horizon is a lightweight Pi-hole-companion that allows network users to temporarily disable Pi-hole without a complex UI, presented on a simple web page. 
Event Horizon is a lightweight Pi-hole-companion designed for controlling Pi-hole's ad blocking feature on-demand by non-technical users who do not need or desire access to the Pi-hole admin web UI. It allows network users to disable Pi-hole's ad blocking for a set duration (configured during install or via event-horizon.conf any time after install) through a simple, user-friendly web interface. The service uses the Pi-hole API to interact with one or multiple Pi-hole instances, and it logs each action for transparency and administration ease.

Event Horizon communicates with Pi-hole v6 using its public HTTP API. No Pi-hole source code is used or redistributed.

Keeping with Pi-hole's block-hole theme, the name Event Horizon was inspired by the concept of a critical boundary in space - once something crosses it, there's no turning back. Much like the event horizon, this service puts control into the hands of users on your network. When the ad blocker is disabled, you cross a threshold into a filterless web experience. Just as space's event horizon signifies a point of no return, disabling your adblocker marks a shift in how you experience the internet.

![Event Horizon Main Page](/images/event-horizon-main.png)

![Event Horizon Results](/images/event-horizon-results.png)

## Who is Event Horizon for?

- Anyone who manages Pi-hole for other people who dneed a simple way to disable blocking on-demand. The creator of this service deployed Pi-hole on their grandparent's network as a way of protecting them from malicious ads, but since they are non-technical, needed a way for them to disable blocking on two piholes with a single click - no complex UI, no logins.

## How does Event Horizon get displayed?

- Option 1: Via link or bookmark. Access Event Horizon from any device on the network (firwall permitting) on demand via a link, device bookmark
- Option 2: Create a custom "block" html page in each Pi-hole which contains a link to this page or an iframe

---

## Features

- **Works with Pi-hole v6**: If you're running Pi-hole v5 or earlier, this service will not work. Support for v5 may be added later, but is not planned at this time.
- **Manage Pi-hole instances with one button**: You can manage multiple Pi-hole instances from a single Event Horizon server with a single button.
- **User Friendly Web Interface**: A simple, mobile-friendly interface with a single button to disable Pi-hole's ad blocking for a specified duration (specified in server config).
- **API Integration**: The service interacts directly with Pi-hole's HTTP API, no SSH or changes required to Pi-hole other than generating an application password via the Pi-hole web UI.
- **Logs**: Logs are automatically generated each time the ad blocker is disabled, and the logs are accessible through the web interface. You decide whether or not to include a link on the main page for the logs.
- **Customizable Disable Time**: The default duration is 10 minutes, but this can be configured during installation.

---

## Security Warning

> **IMPORTANT**: This service intentionally **does not** include any form of authentication or encryption (TLS). You must firewall this service yourself to restrict access from access outside your network.

---

## Installation

Event Horizon can be installed using either the automated installer script or Docker. Choose the method that best fits your environment.

### Requirements

- **Pi-hole v6**: You should already have at least one Pi-hole instance in operation. This service works with Pi-hole v6 only at this time.
- **Internet Access**: To download the required files.
- **A system to run Event Horizon on**: This service is lightweight and can run alongside Pi-hole on the same Raspberry Pi, or you can use a dedicated piece of hardware.

Event Horizon is lightweight by design and can be run alongside Pi-hole, even on a Raspberry Pi. Only one instance of Event Horizon is needed for a group of Pi-holes, as it is able to manage multiple Pi-hole instances.

### Option 1: Automated Installation Script

1. **Run the installer**:
   The easiest method is to use `curl` to download and execute the installer:

```
curl -fsSL https://raw.githubusercontent.com/jbswaff/event-horizon/main/install.sh | sudo bash
```

2. **During installation**, you will be prompted to provide the following configuration details:
- The **Pi-hole IP addresses** and **API password** for each Pi-hole instance. It is recommended to use an application password generated from the Pi-hole web UI instead of your top-level password.
- The **duration for disabling ad blocking** (in minutes).
- Whether to **show a link to logs** on the main page.

The installation script will automatically configure the necessary files and services for you. The installer will automatically test API connectivity during the installation process, alerting you to an issue early.

### Option 2: Docker Installation

1. **Clone the repository**:
```bash
git clone https://github.com/jbswaff/event-horizon.git
cd event-horizon
```

2. **Build the Docker image**:
```bash
docker build -t event-horizon:latest .
```

3. **Create a configuration file**:
   Copy the sample environment file and edit it with your Pi-hole configuration:
```bash
cp .env.sample .env
```
   Then edit `.env` with your Pi-hole details:
```bash
PORT=8080
DISABLE_MINUTES=10
SHOW_LOG_LINK=true
PIHOLE_COUNT=1
PIHOLE_1_IP=192.168.1.100
PIHOLE_1_PASSWORD=your_api_password_here
```

4. **Run the container**:
```bash
docker run -d \
  --name event-horizon \
  -p 8080:8080 \
  -v /var/log/event-horizon:/var/log/event-horizon \
  --env-file .env \
  --restart unless-stopped \
  event-horizon:latest
```

5. **Access Event Horizon**:
   Navigate to `http://<your-server-ip>:8080` in your browser.

## Configuration File

The configuration file is located at `/etc/event-horizon/event-horizon.conf`. It contains all the configuration options for the service, including Pi-hole instances and settings for the disable time and logs visibility.

You can manually edit this file to update settings if needed, but the installation script will handle the configuration by default.

---

## Logs

The logs for each time ad blocking is disabled are stored in `/var/log/event-horizon/requests.log`. You can view the logs directly from the web interface if you enabled the log link during installation. If you chose not to display a link to logs on the main page, you can still access the logs here: http://<Event-Viewer-IP-or-Hostname>:PORT/logs

![Event Horizon Logs](/images/event-horizon-logs.png)

The logs contain:

- The **IP address** of the user who triggered the action.
- The **Pi-hole instances** affected and their responses.
- The **time** when the action was performed. Be sure to check the time zone of the system running Event Viewer to avoid confusion later.


---

## Development

For local development with hot-reload capabilities, use Docker Compose:

1. **Create a `.env` file** from the sample and configure your Pi-hole settings:
```bash
cp .env.sample .env
```

2. **Start the development environment**:
```bash
docker compose up
```

The development container uses `watchfiles` to automatically reload the server when you make changes to [server.py](server.py). Your local [server.py](server.py) file is mounted into the container, so any edits you make will immediately trigger a reload.

3. **Access the development server**:
   Navigate to `http://localhost:8080` in your browser.

4. **Stop the development environment**:
```bash
docker compose down
```

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

## This is an early release

This is an early release, so you may encounter bugs. If you do, please report them via [GitHub Issues](https://github.com/jbswaff/event-horizon/issues).
. When reporting an issue, please include the following details:

1. Event Horizon version or commit hash
2. Pi-hole version
3. Event Horizon log files, if applicable
4. Steps to reproduce
5. Screenshots or error messages
6. Network setup (are you running VLANs? Is there any other relevent information?)
7. Any changes made to the source code

**Acknowledgments**
- [Pi-hole](https://pi-hole.net) for providing an easy-to-use and powerful ad-blocking solution.
- The Python community for their continued work on the Python ecosystem.
- The r/pihole community for the encouragement to build this service into a deployable package.
- This project is developed and maintained by Joshua Swafford for the Pi-hole community.


**Legal Notice**:
- Pi-hole is a registered trademark of Pi-hole, LLC.
- This project is neither affiliated with nor endorsed by Pi-hole, LLC.
- Event Horizon interacts with Pi-hole exclusively through its public HTTP API.
- No Pi-hole source code is used, redistributed, or modified in any way by Event Horizon.

