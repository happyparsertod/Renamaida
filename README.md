Renamaida Plugin for IDA Pro
Introduction
Renamaida is a plugin for the IDA Pro disassembler that helps to rename unknown functions in firmware binaries. It does this by using pre-generated signature files to identify functions imported from open libraries or statically linked, and then renaming them based on their signatures.

Installation
To use Renamaida, simply copy the plugin into the "plugins" directory of your IDA Pro installation. Then, when you open a firmware binary in IDA Pro, you can select Renamaida from the "Edit" menu.

Usage
Before using Renamaida, you'll need to generate a signature file for the library you're working with. To do this, use the "Renamaida signature generator" script to create a JSON file containing the signatures of all functions in the library. Save this file in the "Renamaida signature base" folder.

To rename unknown functions in a firmware binary, open the binary in IDA Pro and select Renamaida from the "Edit" menu. A window will appear where you can select the JSON signature file to use for renaming. Once you've selected a file, Renamaida will use the signatures to rename any unknown functions in the binary that match the signatures.

Contributing
If you encounter any issues with Renamaida, or would like to contribute to its development, please submit an issue or pull request on the GitHub repository.
