# Setup Relapse with Systemd
This is a setup for managing relapse with a user contributed systemd unit 
file. It provides a `matrix-relapse` systemd unit file that should be tailored 
to accommodate your installation in accordance with the installation 
instructions provided in
[installation instructions](https://clokep.github.io/relapse/latest/setup/installation.html).

## Setup
1. Under the service section, ensure the `User` variable matches which user
you installed relapse under and wish to run it as. 
2. Under the service section, ensure the `WorkingDirectory` variable matches
where you have installed relapse.
3. Under the service section, ensure the `ExecStart` variable matches the
appropriate locations of your installation.
4. Copy the `matrix-relapse.service` to `/etc/systemd/system/`
5. Start Relapse: `sudo systemctl start matrix-relapse`
6. Verify Relapse is running: `sudo systemctl status matrix-relapse`
7. *optional* Enable Relapse to start at system boot: `sudo systemctl enable matrix-relapse`
