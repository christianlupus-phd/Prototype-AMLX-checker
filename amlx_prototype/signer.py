
import amlx_prototype
import os

"""
    This class allows to build a container from a pre-existing FMU

    This is rather hacky and should only show the idea:
    the generated container has a hardcoded name BouncingBall inside the container and the loading of the PKI should be moved to its own library at best
"""
class Signer:
    def __init__(self, args) -> None:
        self.__args = args

    def run(self):
        # Create a builder for the AMLX container based on boilerplate and the user-provided FMU
        amlx = amlx_prototype.container.AMLContainerBuilder(self.__args.boilerplate_path[0], self.__args.fmu[0])
        amlx.init()
        
        # The container should be a valid one, so use default plugin
        callbackPlugin = amlx_prototype.container.DefaultFmuSpoofPlugin()

        # This is only a hack. The parameters in self.__args are not the same. Instead...
        bootstrapper = amlx_prototype.bootstrapper.Bootstrapper(self.__args)
        # ... put the PKI code into its own module
        lcd = bootstrapper.getLocalKeyInfrastructure()

        # Put all data in the XML structures
        amlx.updateDTData(lcd, callbackPlugin)

        # Some syntactic sugar to handle the path names from the command line interface
        if self.__args.output is None:
            outfile = f'{self.__args.fmu[0]}.amlx'
        else:
            outfile = self.__args.output[0]
        dirname = os.path.dirname(outfile)
        if dirname != '':
            os.makedirs(dirname, exist_ok=True)
        if self.__args.pki is None:
            pkiPath = os.path.join(self.__args.base[0], 'pki')
        else:
            pkiPath = self.__args.pki[0]

        # Create the container and save it to the disk
        amlx.createContainer(outfile, pkiPath, callbackPlugin)
