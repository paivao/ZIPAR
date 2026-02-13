# ZIPAR

The Zip IPA Reconstructor (or Zip IPA Retriever, if you prefer).

This project re-creates an IPA from an installed Application in an jailbroken iOS device.

This project started as a fork of the famous [**frida-ios-dump**](https://github.com/AloneMonkey/frida-ios-dump)

> The name ZIPAR came as it is an foreignism in portuguese language, that literally means "to zip".

## Installation

To use this tool, it is **highly recomended** to use an virtualenv (although not necessary).
A quick bootstrap:

- `python3 -m venv venv` (the last parameter can be any name to a folder to be venv)
- `source venv/bin/activate`

After that, just install using pip:

`pip install zipar`

Another option is to clone this repo, and to install via **pip**, or run via **uv**.

- `git clone https://github.com/paivao/ZIPAR`
- `pip install .`

## Usage

This tool connects to iOS device using Frida. By default, it uses USB, but can use an remote connection too.

It will attach to the requested application, either by name, bundle id or PID. If name or bundle is used,
but the application is not running, it will be spawned first.

It can, also, attach to the frontmost application.

For more information, use `zipar -h` to get help.

### Issues

If the following error occurs, please open the application before dumping:

* causes device to reboot
* lost connection
* unexpected error while probing dyld of target process

## Contribute

This project uses **uv** to manage, so you need to install it first. It can be installed using `pip` or `cargo`.

The Frida scripts need to be compiled using `frida-compile`, and the package `frida-tools` is needed to run it.

If you modify any *Typescript* code, you need to run `npm run build` inside *agent* directory.
