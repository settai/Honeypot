## Honeypot Projet :

In computer terminology, a honeypot is a computer security mechanism set to detect, deflect, or, in some manner, counteract attempts at unauthorized use of information systems. Generally, a honeypot consists of data (for example, in a network site) that appears to be a legitimate part of the site that seems to contain information or a resource of value to attackers, but actually, is isolated and monitored and enables blocking or analyzing the attackers. This is similar to police sting operations, colloquially known as "baiting" a suspect.

This project is an emplementation of a Honeypot able to detect ports scanning, Arp poisoning and spoofing by analysing the packets transmitted across the network.

## Preview

![Preview](https://github.com/settai/Honeypot/blob/main/preview.gif)

## Prerequisites and Deployement

*This program requires Java and Jnetpcap

### 1. Downloading the project

This project can be cloned from this link

```
https://github.com/settai/Honeypot.git
```

### 2. Running or modifying this project

*Include the jnetpcap library on the class path*

```
cd src\honeypot
javac *.java
java Honeypot.java
```