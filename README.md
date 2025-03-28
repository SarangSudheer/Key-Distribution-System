# Key-Distribution-System

###Intrduction
In this digital era, conducting a secure communication and data protection is very much important.
So, in order to address this problem I have come up with a Key Distribution System, where symmetric encryption is taken care by a Centralized Key Management System and asymmetric key is taken care by a Public Key Interface (PKI). This provides a secure way of exchanging encryption and decryption keys between 2 parties.

This Key Distribution System is designed to handle the following things:
  i. Generate a suitable symmetric and asymmetric keys
  ii. Storing the generated keys
  iii. Exchanging keys using Diffie-Helman for symmetric key and PKI based certification for asymmetric keys
  iv. Revocation of keys

In a nutshell, this project focuses on generating, storing and exchanging cryptography keys securly by mitigating Man In the Middle Attack (MIMA) and revocing keys in case of key compromise.
