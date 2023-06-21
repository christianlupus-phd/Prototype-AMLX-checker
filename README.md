# Prototype of signing FMUs using AMLX containers and cryptography

> ⚠️ **IMPORTANT** ⚠️  
>  This is just a prototype to show general functionality.
> It is not productive code.

## Installation

This tool needs some python dependencies.
It is adviced to use a virtual environment to handle these dependencies.
After checking out the repository, you can create a new virtual python environment by calling

```
python -m venv venv
```

After that, you need to activate that environment.
Under windows, you have to source `venv/Scripts/activate` and under Linux `venv/bin/activate`.
Keep the console open as closing the console means you have to reactivate the environment.

Now, install all dependencies by calling
```
pip install --upgrade pip
pip install -r requirements.txt
```
This might take some time but will install all dependencies automatically.

## Usage

This tool provides three modes currently:

- **bootstrap**: This will generate a test PKI using self-signed certificates and a fixed chain length. Also, some test files are prepared.
- **check**: This allows to check a container if the hash and the signatures are valid
- **sign**: This allows to create new containers from custom FMUs. Note, this is very rough and will not produce good containers.

You can call the tool by running
```
python run.py <common options> <command> <command options>
```
You can put `-h` for both _common options_ and _command options_ to get a list of possible options.
With `-v` in the _common options_ you can get more information from the tools.

The `command` is one of the three options `bootstrap`, `check`, and `sign`.

For a detailed list of per-command options, please have a look at the help output of the code itself.

### Bootstrap

The bootstrap let's you start with the tool.
You can trigger this in its basic form by
```
python run.py bootstrap
```
This will create a folder `bootstrap` with the PKI (in sub-folder `pki`).
The PKI is a root certificate, an intermediate certificate, a vendor certificate, and a FMU (leaf) certificate.
There are not additional attributes or restrictions added to the certificates to simplify usage.
By providing the `--pki` CLI option, you can specify another folder to put the PKI.

The bootstrap is combined with an example FMU that is packed into an AMLX container.
The packaging is handled such that there are three ocntainers built:
one container is a normal container as one would share it.
The other two are built such that they simulate different issues like a broken file or an attack.
The containers are automatically output to the folder `fmus` inside the `bootstrap` folder.
You can customize the path as well.

### Checking

If you get a FMU-embedded container, you want to check if it is legit.
To do so, the check feature is present.
It reads the container and extracts all relavant data.
First, it checks if the AMLX contains a valid chain and the chain can be trusted.
If yes, the tool can either just confirm validity (to check it) or output the embedded FMU file for usage with legacy FMI-compatible tools.

To check a container `myfmu.amlx` with the trust anchor (root certificate) `root.pem`, you would call
```
python run.py check -r root.pem myfmu.amlx
```

### Signing

Finally, you can build you own AMLX containers.
This allows you to sign and pack with the configured PKI data teh FMU and store in an AMLX container.

An example would simply be
```
python run.py sign myfmu.fmu
```
This will read the file `myfmu.fmu` and create a new AMLX container called `myfmu.fmu.amlx` that contains the hash, signature, and cryptographic data needed to verify the container.
You can use the `verify` subcommand to test it.

## Restrictions

This is only a bare protoype to show the functionality as a proof of concept.
There are zillions of bugs, issues, and flaws:

- The FMU name is fixed in the container
- The operating system root certificates are plainly ignored
- There is no policy algorithm involved, this needs a complete implementation
- The PKI is just a statically built one, this needs to be replaced with appropriate methods
- The number of certificates in a chain is mainly hardcoded
- ... and many, many more

## License

This work is published under MIT license.
For more details see the file [LICENSE.md](LICENSE.md).

(C) Christian Wolf, 2023
