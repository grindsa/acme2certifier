# Containerized wsgi installation using apache2

This should be the fastest and most convinent way to deploy acme2certifier. After installation acme2certifier will run inside a minimalized ubunbtu 18.04 container using apache2 as webserver.

Acme2certifier needs to store its database (`acme_srv.db`), ca_handler (`ca_handler.py`) and configuration file (`acme_srv.cfg`) on a persistent data-storage. Thus, it is recommended to create a volume and mount it during the start of the container.

The volume can be created with the below command.

`root@docker-test:~# docker volume create --name acme2certifier`

I am not planning to provide readymade container images as I do not have the bandwidth to maintain them. Instead, the files and scripts you need to create a container are part of the git repository. 

You can download them by using the link below.

`root@docker-test:~# curl https://raw.githubusercontent.com/grindsa/acme2certifier/master/examples/docker_wsgi.tgz --output docker_wsgi.tgz`

After download the archive must be enpackted

`root@docker-test:~# tar xvfz docker_wsgi.tgz`

After entering the directory 

`root@docker-test:~# cd acme2certifier`

You can build the container 

`root@docker-test:/home/joern/acme2certifier# docker build -t acme2certifier .`

All components needed to create the container will be downloaded automatically. The time to build the container depends from quality and speed of your internet connection but should not take more than 15 min.

If the container creation completed without errors the container can be started by using the command below.

`root@docker-test:/home/joern/acme2certifier# docker run -p 80:80 -p 443:443 -v acme2certifier:/var/www/acme2certifier/volume --name=acme2certifier --restart=always -d acme2certifier`


The entry-point script will check during the start process if a configuration file and a ca_handler do exist on the volume. If these files do not exist the below examples will be copied to the volume.

- [acme_srv.cfg file](/examples/acme_srv.cfg) from the example directory
- [stub_handler](/examples/ca_handler/skeleton_ca_handler.py) from the example/ca-handler directory

The container should be visible in the list of active containers

```
root@docker-test:/home/joern/acme2certifier# docker ps -a
CONTAINER ID        IMAGE                 COMMAND                  CREATED             STATUS              PORTS                                      NAMES
db925fc41668        acme2certifier        "/docker-entrypoint.…"   13 seconds ago      Up 12 seconds       0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp   acme2certifier
```

Its should already be possible to access the directory Ressource (192.168.14.133 is the IP of my container-host and must be modified according to your setup)

```
root@ub18-04:~# curl http://192.168.14.133/directory
{"newAuthz": "http://192.168.14.133/acme/new-authz", "newNonce": "http://192.168.14.133/acme/newnonce", "newAccount": "http://192.168.14.133/acme/newaccount", "newOrder": "http://192.168.14.133/acme/neworders", "revokeCert": "http://192.168.14.133/acme/revokecert", "keyChange": "http://192.168.14.133/acme/key-change", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>", "name": "acme2certifier", "version": "0.8"}, "09e7bda62ca443cfb495ca6e36469556": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417"}root@ub18-04:~#
```

Both configuration file and ca_handler must be modified according to your setup. To reload the modified files the container should be restarted.

```
root@docker-test:/home/joern/acme2certifier# docker stop acme2certifier
root@docker-test:/home/joern/acme2certifier# docker start acme2certifier
´´´
