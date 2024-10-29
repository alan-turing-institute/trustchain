# ION launchd User Agents

The scripts in this directory simplify and automate the process of launching ION on macOS.

Before running any script, make sure you have installed ION by following the installation guide in the [Trustchain docs](https://alan-turing-institute.github.io/trustchain/ion/).

To launch ION, run the following command from the repository root:
```
./scripts/launchd/autostart_ion.sh
```
ION will then automatically start on user login.

To stop ION (and disable automatic starting), run:
```
./scripts/launchd/stop_ion.sh
```
