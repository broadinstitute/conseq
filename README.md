##### Table of Contents  
* [Conseq Config Reference](#conseq-config-reference)
* [Command Line Reference](#command-line-reference)

# Conseq 
(Pronounced "con-SIK" as in "consequence")

Conseq is a tool for running sequences of transformations or other operations.

More on the motivation and details seen this slide deck: https://docs.google.com/a/broadinstitute.com/presentation/d/1LsRymTEKmqDxACDnMIx1z_Y2dQtY7TNpb5PAFyK0OQM/edit?usp=sharing

<a name="conseq-config-reference"/>
# Conseq Config Reference

A conseq config file consists of xrefs, variables and rules.  

### Variables

Variables can be defined with the "let" keyword.  For example:

```
let label="run10"
```

This variable is accessible in as "config.label" and can be overriden by the command line by adding arguments of the form "-c label=XXX"

Individual scripts should only define new lowercase variables.  Variables in uppercase are used by conseq for configuration and are defined under special variables below. 

Special variables:

* **DL_CACHE_DIR** The directory that remote files are cached in after downloading.
* **SCRIPT_DIR** The directory containing the conseq script being run.
* **PROLOGUE** Text which is preprended to each shell script that's generated for executing a rule.  Useful for configuring the environment before the command runs.

### Xref

Xrefs create artifacts which represent entities, identified by a url-style names, that are outside of conseq.  Supported urls are:

```
taiga://...
ssh://host/path/...
http://host/path/...
```
or a path to a locally accessible file.

example:
```
xref http://data/all.csv {"name": "data"}
```
will result in an artifact with properties "name" and "filename" after the url has been fetched.

### Rules

The most important concept is are "rules".  These define what to run (generally, a script) when the required inputs exist.  

Rules have three sections, each optional: "inputs", "outputs" and "run"

Inputs define a query which will be executed to find the artifacts needed to execute the rule, and the name of the variable that the object will be bound to when its found.

For example:

Assume we have the following artifacts:

```
type       name
cell_line  NCI-543
cell_line  MM3

type       cellline_name
WGS        NCI-543
WGS        NCI-433
```
And the following rule:

```
rule process_cellline:
  inputs: cellline={"type": "cell_line"}
  ...
```
Will run the "process_cellline" rule once for each artifact that has a "type" property with the value "cell_line".   In this example, process_cellline would be run twice.

One can fetch multiple objects, by providing a comma seperated list such as:

```
rule process_cellline:
  inputs: cellline={"type": "cell_line"}, data={"type": "WGS"}
  ...
```

This will run process_cellline once for every combination of "data" and "cell".   In this example, process_cellline would be run four times.

Often we want to not run every possible pair, but have the right pairs.  In this particular example, it'd only make sense to have the have the data for the cell line that was selected.  You can do this by not giving a constant (in quotes) but using a variable.

```
rule process_cellline:
  inputs: cellline={"type": "cell_line", "name": name}, data={"type": "WGS", "cellline_name": name}
  ...
```

With the artifacts above, this will result in a single execution of process_cellline where cellline will be {"cell_line": "NCI-543"} and data will be {"type": "WGS", "cellline_name": "NCI-543"}

Lastly, one can fetch multiple artifacts by prefixing the query with "all" 

```
rule process_cellline:
  inputs: cellline=all {"type": "cell_line"}
  ...
```

will execute process_cellline once, with `celllines = [{"type": "cell_line", "name": "NCI-543"}, {"type": "cell_line", "name": "MM3"}]`

### run statement

Example:

run "X"

Executes "X"

run "X" with "Y"

Write "Y" to a temp file and run "X tempfilename".   For R, write

run "Rscript" with "library(...) ..."

### Publishing artifacts

As part of running a rule, we should publish the results back to conseq.   For simple cases, we can include a "outputs" clause where we can list a static list of artifacts which will be published if and only if all run statements execute successfully.

Alternatively, one can include a run step which uses python and the "conseq" module to publish.

example:

```
   run "python" with """
     import conseq
     ...
     conseq.publish(dict(name=X, ...), dict(...), ... )
     """
```

<a name="conseq-command-line-reference"/>

# Command Line Reference

You can get help on all conseq commands by running `conseq --help`

However, the most common commmand you will run is: running all rules in a config file. (Assuming name of file is "all.conseq" in this case):
```
conseq run all.conseq
```

Another common case is listing all of the artifacts stored in the conseq database:
```
conseq ls
```

Special key/values $file, $xref, $hash, $value

Requires:
    mem=x
    cpu=y, capability
    
define named execution profiles:
    sge: host=foo, username=y

define-exec-profile foo
    resources:
        mem: x
        cpu: y
        aws
    type: sge|local|ssh|docker|kubernetes
    parameters:

firecloud submission would be better done as a local job making an API call I think...

default profile:
    1 cpu, infinite memory

resources are either: a number or a tag.  If resources are a tag, then a job marked with tag can only execute against a profile also with that tag.  (it is a nonconsumable resource but validated)
This is a bit silly because it's suggests the config contains a bad exec-profile.  However, it might be useful in guarenteing jobs are run against the right kind of profile.  If validation fails, 
the job should be treated as a failure.

resources which have a number are consumable.  While a job is executing it holds on to a reservation of that resource.  If the resource is insufficient the job will not be considered as availible for 
execution.  (Should do a validation that the job is requesting < the max resource.  If > that is a hard error and job should fail as opposed to wait forever)

Update run syntax:
    [using EXECPROFILE] run CMD [with CONTENT]

Should I make helper.py into a go binary?  Would enable me to get/exec/put with no extra deps.  Would likely have to bake binary into image for execution on kubernettes. (On second thought, can accomplish this by having two containers, one with bin and the target container and share the bin volume)


