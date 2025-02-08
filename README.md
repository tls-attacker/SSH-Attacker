# SSH-Attacker

A framework for automated analysis of the SSH protocol.

SSH-Attacker is a Java-based framework for analyzing SSH libraries. It is able to send arbitrary protocol messages in an arbitrary order to the SSH peer, and define their modifications using a provided interface. This gives the developer an opportunity to easily define a custom SSH protocol flow and test it against his SSH library.

**Please note:**  *SSH-Attacker is a research tool intended for SSH developers and pentesters. There is no GUI and no green/red lights.*

## Compiling and Running

In order to compile and use SSH-Attacker, you need to have Java and Maven installed. On Ubuntu you can install Maven by running:

```bash
$ sudo apt-get install maven
```

SSH-Attacker currently needs Java JDK 21 to run. If you have the correct Java version, you can run the `mvn` command from the SSH-Attacker directory to build the project:

```bash
$ git clone git@github.com:tls-attacker/SSH-Attacker.git
$ cd SSH-Attacker
$ mvn clean install
```

Alternatively, if you are in a hurry, you can skip the tests by using:

```bash
$ mvn clean install -DskipTests=true
```

The resulting jar files are placed in the "apps" folder.

If you want to use this project as a dependency, you do not have to compile it yourself and can include it in your pom
.xml as follows.

```xml
<dependency>
    <groupId>de.rub.nds.ssh.attacker</groupId>
    <artifactId>ssh-attacker</artifactId>
    <version>2.0.0</version>
    <type>pom</type>
</dependency>
```

SSH-Attacker ships with demo applications which provide you easy access to SSH-Attacker functionality.

You can run SSH-Attacker as a client with the following command:

```bash
$ cd apps
$ java -jar SSH-Client.jar -connect [host:port]
```

or as a server with:

```bash
$ java -jar SSH-Server.jar -port [port]

```

Furthermore the SSH-Attacker adds a support for a SSH-MITM, by doing two different key exchanges on client and server-side and then forwarding the messages in a proxy manner. This can help SSH developers to get more specific insights into the protocol flow and message structure. The SSH-Mitm can be started like:

```bash
$ java -jar SSH-Mitm.jar -connect [host:port] -accept [port]
```

SSH-Attacker also ships with some example attacks on SSH to show you how easy it is to implement an attack with SSH-Attacker.
You can run those examples with the following command:

```bash
$ java -jar Attacks.jar [Attack] -connect [host:port]
```

Although these example applications are very powerful in itself, SSH-Attacker unleashes its full potential when used as a programming library.

## Code Structure

![Project Structure](/resources/doc/SSH-Attacker-Overview.png?raw=true)

SSH-Attacker consists of several (maven) projects:
- SSH-Client: A simple, highly configurable SSH client using SSH-Attacker
- SSH-Core: The protocol stack and heart of SSH-Attacker
- SSH-Core-OQS: SSH post-quantum crypto support using liboqs
- SSH-Mitm: A simple man-in-the-middle application for SSH
- SSH-Server: A simple, highly configurable SSH server using SSH-Attacker

## Features

Currently, the following features are supported:
- SSHv2 (RFC4251 and related)
- Support for Transport Layer (RFC4253), Authentication (RFC4252), and Connection Protocol (RFC4254)
- Supported message types: [Messages](https://github.com/tls-attacker/SSH-Attacker/tree/main/resources/doc/MESSAGES.md ':include')
- Supported crypto algorithms: [Algorithms](https://github.com/tls-attacker/SSH-Attacker/tree/main/resources/doc/ALGORITHMS.md ':include')
- Some extensions (proprietary and RFC8308)
- Client, Server, and MitM

## Usage

Here we present some very simple examples on using SSH-Attacker.

First, you need to start a SSH server (*please do not use public servers*). For uncomplicated start of a SSH server, we provide a SSH-Docker-Library(https://github.com/tls-attacker/SSH-Docker-Library) in addition to the SSH-Attacker, which keeps different server and client docker images of known SSH-implementations.

If you want to connect to a server, you can use this command:

```bash
$ cd SSH-Attacker/apps
$ java -jar SSH-Client.jar -connect localhost:22
```

In case you are a more experienced developer, you can create your own SSH message flow by writing Java code. For example:

```java
Config sshConfig = config.createConfig();
WorkflowTrace trace = new WorkflowTrace();
trace.addSshActions(new SendAction(new VersionExchangeMessage()),
                    new ReceiveAction(new VersionExchangeMessage()),
                    new ChangePacketLayerAction(
                        sshConfig.getDefaultClientConnection().getAlias(),PacketLayerType.BINARY_PACKET));
State state = new State(sshConfig, trace);
DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
executor.executeWorkflow();
```

SSH-Attacker uses the concept of `WorkflowTrace`s to define a message flow. Each `WorkflowTrace` consists of a list of actions which are executed in sequence.

We know many of you hate Java. Therefore, you can also use an XML structure and run your customized SSH protocol from XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<workflowTrace>
    <Send>
        <messages>
            <VersionExchange/>
        </messages>
    </Send>
    <Receive>
        <expectedMessages>
            <VersionExchange/>
        </expectedMessages>
    </Receive>
    <ChangePacketLayer to="BINARY_PACKET"/>
</workflowTrace>
```

Given this XML structure, located in `SSH-Attacker/resources/examples`, you would just need to execute (replacing `[host]` and `[port]`):

```bash
$ java -jar apps/SSH-Client.jar -connect [host]:[port] -workflow_input resources/examples/workflow.xml

```

## Dockerfile

Additionally we provide a docker image, located in `SSH-Attacker/Dockerfile`, which can be used to run the different SSH-Attacker modules directly in a container. When running the image use the --target [ssh-client, ssh-server, ssh-mitm, attacks]docker flag to specify which module should be executed as entrypoint in the docker container.

## Modifiable Variables

SSH-Attacker uses the concept of Modifiable Variables to allow runtime modifications to predefined Workflows. Modifiable variables allow one to set modifications to basic types after or before their values are actually set. When their actual values are determined and one tries to access the value via getters the original value will be returned in a modified form accordingly. More details on this concept can be found at the [ModifiableVariable repository](https://github.com/tls-attacker/ModifiableVariable).

```java
ModifiableInteger i = new ModifiableInteger();
i.setOriginalValue(30);
i.setModification(new AddModification(20));
System.out.println(i.getValue());  // 50
```

In this example, we defined a new ModifiableInteger and set its value to 30. Next, we defined a new modification AddModification which simply returns a sum of two integers. We set its value to 20. If we execute the above program, the result 50 is printed.

We can of course use this concept by constructing our SSH workflows. Imagine you want to test the channel management of a ssh server. With SSH-Attacker, you can do this as follows:

```java
ChannelOpenSessionMessage channelOpenSessionMessage = new ChannelOpenSessionMessage();
        ModifiableInteger i = new ModifiableInteger();
        channelOpenSessionMessage.setConfigSenderChannelId(1337);
        i.setModification(new IntegerAddModification(100));
        channelOpenSessionMessage.setSenderChannelId(i);//1437
```

The ChannelOpenSessionMessagePreparator wil overwrite the ModifiableInteger holding the `senderChannelId` with the `configSenderChannelId`, so the original value will be set to 1337 by that. When accessing the `senderChannelId` for serializing the message, the value will be returned in modified form:

```xml
<ChannelOpenSession channel="1337">
                <messageId>
                    <originalValue>90</originalValue>
                </messageId>
                <channelTypeLength>
                    <originalValue>7</originalValue>
                </channelTypeLength>
                <channelType>
                    <originalValue>session</originalValue>
                </channelType>
                <windowSize>
                    <originalValue>2147483647</originalValue>
                </windowSize>
                <packetSize>
                    <originalValue>32768</originalValue>
                </packetSize>
                <senderChannelId>
                    <IntegerAddModification>
                        <summand>100</summand>
                    </IntegerAddModification>
                    <originalValue>1337</originalValue>
                </senderChannelId>
</ChannelOpenSession>
```

As you can see, we explicitly increased the `senderChannelId` by 100 through the modification.

## Advanced Features

Some actions require context, or configuration to be executed correctly. For example, if SSH-Attacker tries to send a `KeyExchangeInit` message, it needs to know which values to
put into the message, e.g., which crypto algorithms to use. SSH-Attacker can draw this information
from a configuration file, thus we added some default config files to `resources/configs`, which allow running the SSH-Attacker in different scenarios.
Values which are determined at runtime are stored in the `SshContext` class. When a required value is missing from context, a chooser will determine where to load the value from. In the default impelementation, the value from `Config` is selected. You may specify your own configuration file from command line with the "-config" parameter. Note that if you do not explicitly define a default value in the config file, SSH-Attacker fills
this gap with hardcoded values.
