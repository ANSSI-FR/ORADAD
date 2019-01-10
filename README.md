# ORADAD
~~ Outil de Récupération Automatique des Données de l'Active Directory ~~

This tool helps dumping Active Directory data via LDAP to assist security audit assignments. It has been designed to be easier to use and extend than [DirectoryCrawler](https://github.com/ANSSI-FR/ADCP-DirectoryCrawler). It also supports multi-domain forests.

## Configuration

Edit the `<config>` section of `config-oradad.xml`.

## Usage

`ORADAD.exe <outputDirectory>`

The configuration is read from `config-oradad.xml` which must be stored next to `ORADAD.exe`.
