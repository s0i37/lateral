# Lateral

Reaching the goal may require multiple forwarding of ports or vpn tunnels.

![pivoting3](https://user-images.githubusercontent.com/22872513/128855096-1da1074b-04c7-4449-be51-d7e0c78b308c.png)

Сlassic pivoting is not always easy and cannot be 100% automated.

## **Lateral movement** without **pivoting**.

The solution - use the same ports for port forwarding as for lateral movement.

![recursive](https://user-images.githubusercontent.com/22872513/128854990-4de0b65c-115e-4758-bf74-7718b5ef5c35.png)

It may looks like every new shell opens from a previous target.

And in fact, all connections will only take place between victims.

![iftop](https://user-images.githubusercontent.com/22872513/128855822-b9fadbb9-9c6f-4346-83d8-eaa933a5a152.png)

## Builtin socks-proxy

Traffic of any application can be redirected through msrpc tunnels.

![psexec](https://user-images.githubusercontent.com/22872513/128856193-487cbc87-25cb-44a2-bcbf-83cfe98bb604.png)

The output node will be the current victim.

![shells2](https://user-images.githubusercontent.com/22872513/128856256-ca62a79f-0d30-4456-8277-e942299d7729.png)

## Scripting

And now lateral movement can be fully automated.

![python-api2](https://user-images.githubusercontent.com/22872513/128856366-95919d1b-6f36-435c-a0a0-e86af86d6d21.png)

## Problems

* Overheads. Each new chain brings a 5-fold increase in traffic because of RPC transport.
* At the moment there are some problems with WindowsXP (can be fixed)
* `MSRPCProxy` cannot be run through `proxychains`. Because under the hood, it uses localhost connections. You should use transparent proxying in this case (`redsocks`)
* With chains greater than 1, dangling sessions may appear on distant nodes (you can check this `net stop server`). This is due to problems with the blocking calls of the RPC. If there are a lot of hanging sessions (about 20), the RPC may stop working completely and you will lose all remote control (you will need to restart the `server` service manualy). This problem has not been resolved yet, therefore it is recommended to periodically remove the proxy service (`msrpcproxy.py "clear -user admin -pass 123 10.0.0.64`)

## Legal

GPL.

Use only for education purposes or legitimate pentests.
