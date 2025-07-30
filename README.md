# PCSE: Privacy-Preserving Collaborative Searchable  Encryption for Group Data Sharing in  Cloud Computing

## Abstract

 Collaborative searchable encryption for group data sharing enables a consortium of authorized users to collectively generate trapdoors and decrypt search results. However, existing countermeasures may be vulnerable to a keyword guessing attack (KGA) initiated by malicious insiders, compromising the confidentiality of keywords. Simultaneously, these solutions often fail to guard against hostile manufacturers embedding backdoors, leading to potential information leakage. To address these challenges, we propose a novel privacy-preserving collaborative searchable encryption (PCSE) scheme tailored for group data sharing. This scheme introduces a dedicated keyword server to export serverderived keywords, thereby withstanding KGA attempts. Based on this, PCSE deploys cryptographic reverse firewalls to thwart subversion attacks. To overcome the single point of failure inherent in a single keyword server, the export of server-derived keywords is collaboratively performed by multiple keyword servers. Furthermore, PCSE extends its capabilities to support efficient multi-keyword searches and result verification and incorporates a rate-limiting mechanism to effectively slow down adversaries’ online KGA attempts. Security analysis demonstrates that our scheme can resist KGA and subversion attack. Theoretical analyses and experimental results show that PCSE is significantly more practical for group data sharing systems compared with state-of-the-art works.

## Requirements

 The project is intended to run on Ubuntu 24.04 using Python 3.9. The following Python packages are required:

- Charm-Crypto (https://github.com/JHUISI/charm)

## Note

 In TrapGen, the i / (i - j) should be modified to x_i / (x_i - x_j).<img width="871" height="522" alt="image" src="https://github.com/user-attachments/assets/3603cbe8-a885-414d-aad4-64327401f102" />

