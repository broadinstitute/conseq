Consec

Consec is a tool for running sequences of transformations.

Rules define a script to run when the specified inputs exist.

Differences from other workflow executors:
    - Inputs and outputs are "objects", not just filenames, allowing metadata to be stored in properties as opposed to encoding into filenames and directories.
    - Only inputs are specified, not outputs in specfile. This allowing scripts to emit any outputs at run-time at the cost of not being able to predict what all needs to be run before execution.
    - Inputs are defined as queries, allowing easy parameterization of analyses

Concepts:

Objects: a set of key/value pairs.  Special values are denoted as objects with a special key, which starts with "$".  For example {"A": {"$value": "B"}}

Rule: A script and a query defining what inputs the script needs to execute.

Rule Application: A rule with inputs bound to it.

Run statement: A command, and optionally text which will be written to a temp file and passed in as a parameter.

History: inputs, rule_name, outputs

Algorithm:

for each rule:
  run query to find inputs.  Each set of inputs + rule results in a "Rule Application"
  for each resulting "Rule Application":
    if it does not exist already:
      add to the list of existing applications
      Attempt to run the "run statement" for that application
      Add any objects "published" by that run      



# Variables
Individual scripts should only define new lowercase variables.  Variables in uppercase are used by conseq for configuration and are defined under special variables below. 

Special variables:
DL_CACHE_DIR The directory that remote files are cached in after downloading.
SCRIPT_DIR The directory containing the conseq script being run.
PROLOGUE Text which is preprended to each shell script that's generated for executing a rule.  Useful for configuring the environment before the command runs.
