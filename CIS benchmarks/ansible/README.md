# ansible and ansible-lockdown

Outline and what's needed to make this work as simply as possible.


### STEPS
1. Create a "control-server"
	a) This is where you install your requirements and this acts as the server you'll serve commands from. This must be reachable by any and all clients.
2. Install requirements.
	a) Python3, pywinrm, ansible
3. Prepare playbooks and inventorys
	a) Create your own or download templates.
4. Prepare the client
	a) configure winrm or ssh to make the client recieve the benchmarks