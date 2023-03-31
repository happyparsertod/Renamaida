# Renamaida Plugin for IDA Pro
Introduction
Renamaida is a plugin for the IDA Pro disassembler that helps to rename unknown functions in firmware binaries. It does this by using pre-generated signature files to identify functions imported from open libraries or statically linked, and then renaming them based on their signatures.

# Installation
To use Renamaida, simply copy the plugin into the "plugins" directory of your IDA Pro installation. Then, when you open a firmware binary in IDA Pro, you can select Renamaida from the "Edit" menu.

# Usage
Before using Renamaida, you'll need to generate a signature file for the library you're working with. To do this, you'll need to compile the library yourself and ensure that it contains all debug information, including original function names.

Once you have the compiled library, you can use the "Renamaida signature generator" script to create a JSON file containing the signatures of all functions in the library. To use the signature generator, run it from the command line in IDA Pro.

To rename unknown functions in a firmware binary, open the binary in IDA Pro and select Renamaida from the "Edit" menu. A window will appear where you can select the JSON signature file to use for renaming. Once you've selected a file, Renamaida will use the signatures to rename any unknown functions in the binary that match the signatures.

# How the algorithm works
In Renamaida, a dictionary is used in which the keys are instructions of a certain architecture, and their values are the letters of the English alphabet. When creating a JSON signature database, the names of functions are stored in the form of keys and a string of letters of the alphabet that represent the sequence of instructions for this function.

When the plugin is launched, Renemaida creates a signature base of the current binary using the same dictionary, and compares the values of these keys one by one with each other using the Jaro-Winkler Similarity algorithm. Functions are renamed only with similarity values above 0.83 units. An additional limitation is functions with a length of less than 10 instructions, as there is very little data for comparison.

# Contributing
If you encounter any issues with Renamaida, or would like to contribute to its development, please submit an issue or pull request on the GitHub repository.
