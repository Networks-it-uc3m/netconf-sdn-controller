# Centrally Controlled IPSec (CCIPS)

The CCIPS goes beyond the classical point-to-point IPsec setup and provides a centralized architectural solution to control multiple IPsec endpoints or gateways. The CCIPS is composed by a controller and two or more agents, deployed where the IPsec tunnel is established. In this IKE-less case, the RFC specifies a procedure on the re-keying process that is handled by the controller, when requested by the nodes.

On one side, the CCIPS controller architecture relies on a REST API as the central component to provide the NBI and establish sessions with the agents using the [NETCONF protocol](https://www.rfc-editor.org/rfc/rfc6241).

![](https://github.com/Networks-it-uc3m/netconf-sdn-controller/blob/4a477ea4fb024a4ef79ed42aaa6d8f9499adba8f/CCIPS.png)

### Contribution
* SPIRS CCIPS Controller migration from existing standalone python script to an App in ONOS controller.
  * SBI interface YANG using RFC9061 with IPsec agents.
  * NBI for controlling from external system.
# CCIPS APP

To compile and install the CCIPS app, navigate to the project directory and run:
```bash
mvn clean install
```
The installation of the CCIPS app and the activation of the necessary Netconf modules are automatically handled by the onos_critique.sh and setup_controller.sh scripts, which are included in the new [Dockerfile](https://github.com/Networks-it-uc3m/netconf-sdn-controller/blob/4a477ea4fb024a4ef79ed42aaa6d8f9499adba8f/build/Onos/Dockerfile) created for ONOS. If you wish to directly use this Dockerfile with the included scripts, the only change required would be to replace the .oar file with the newly created one after modifying the code, as explained in the wiki: [Initial Setup Steps](https://github.com/Networks-it-uc3m/netconf-sdn-controller/wiki/Installation-and-deployplent#initial-setup-steps).


However, if you prefer to run the basic ONOS 2.7.0 Docker image or execute it locally without Docker, follow these steps:
1. Launch the official ONOS 2.7.0 image or start ONOS locally following the official guide.
2. Execute the script:
```bash
./onos_critique.sh
```
3. Activate the required Netconf bundles:
```bash
/onos/tools/package/runtime/bin/onos-app localhost activate org.onosproject.netconf
/onos/tools/package/runtime/bin/onos-app localhost activate org.onosproject.drivers.netconf
```
4. Install and activate the CCIPS app:
```bash
/onos/tools/package/runtime/bin/onos-app localhost install! target/ccips-app-1.0-SNAPSHOT.oar
```
> [!NOTE]
> It is important to activate the app before loading the netconf-cfg.json file into ONOS.
