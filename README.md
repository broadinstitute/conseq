##### Table of Contents  
* [Conseq Config Reference](#conseq-config-reference)
* [Command Line Reference](#command-line-reference)

# Conseq 
(Pronounced "con-SIK" as in "consequence")

Conseq is a tool for running sequences of transformations or other operations.

More on the motivation and details seen this slide deck: https://docs.google.com/a/broadinstitute.com/presentation/d/1LsRymTEKmqDxACDnMIx1z_Y2dQtY7TNpb5PAFyK0OQM/edit?usp=sharing
or this poster https://drive.google.com/file/d/1FF8ESVbo_LXs4BBfEGAgkbq77ABXyzKu/view?usp=sharing

<a name="conseq-config-reference"/>
# Conseq Config Reference

A conseq config file consists of "add-if-missing" artifact definitions, variables and rules.  

### Variables

Variables can be defined with the "let" keyword.  For example:

```
let label="run10"
```

All variables are accessible in rules as properties of the "config" object. This variable is 
accessible as "config.label" and can be overriden by the command line by adding 
arguments of the form "-c label=XXX"

For configuration that you want to make globally independent of which script
you run can be put into "~/.conseq"

Individual scripts should only define new lowercase variables.  Variables in uppercase 
are used by conseq for configuration and are defined under special variables below. 

The variable **SCRIPT_DIR** is defined at startup and often is used in conseq rules. This variable contains
 the absolute path to the directory containing the conseq script being run. 
 
This is frequently needed as each task runs in its own unique directory. This variable is useful
 for generating relative paths to files which are not artifacts. You can prefix your path with this 
  variable and providing a path relative to the conseq config being executed.

For example, assuming "process.py" is in the same directory as the conseq file, you can 
execute that script from a `run` statement such as:  `run 'python {{ SCRIPT_DIR }}/process.py'`


Additional variables defined at start up:

* **DL_CACHE_DIR** The directory that remote files are cached in after downloading.
* **PROLOGUE** Text which is preprended to each shell script that's generated for executing a rule.  Useful for configuring the environment before the command runs.
* **S3_STAGING_URL** Location where files will be staged and then later pulled from when executing remote jobs
* **AWS_ACCESS_KEY_ID** AWS key ID used for reading/writing to S3
* **AWS_SECRET_ACCESS_KEY** AWS secret used for reading/writing to S3
* **WORKING_DIR** The local dir where scripts are written to and tasks are run from

### add-if-missing

The "add-if-missing" statement creates artifacts if it does not already
exist. List the key value pairs in json-style syntax.


Example:
```
add-if-missing {"name": "sample", "other-property": "more"}
```

will result in an artifact with properties "name" and "other-property".

If you want to refer to file relative to the script being run, use the SCRIPT_DIR
variable to give the absolute path to it.

example:

Assuming you a running a conseq file named "run.conseq" and you want an
artifact referencing a script named "myscript.py" which resides in the same
directory.

```
add-if-missing {"name": "script", filename: {"$filename":"{{config.SCRIPT_DIR/myscript.py}}"} }
```


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

If there's any question what exactly got run, or the what the script looked
like after the template in the "run" statement was expanded you can look at
the files in the "state" directory. There is a subdirectory for each task
run which contains the scripts generated by conseq. That directory is used
as the working directory for running tasks, so outputs are typically also
left behind in the directory.

### run statement

The run statement in a rule defines what to execute for each set of
artifacts found.

Example:

```
run "echo hello"
```

Executes "echo hello" as a shell command.

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




# Conseq Example
## List artefacts

```
conseq ls
conseq ls type=dep-matrix
conseq ls type=dep-matrix library=avana
```

## Remove artefacts

```
conseq rm
conseq rm type=dep-matrix
conseq rm type=dep-matrix library=avana
```
To delete all artefacts, delete the ```state/``` directory

## Add artefacts
* Add to the ```xrefs.conseq``` file before running

## Run conseq pipeline
Run all possible rules, without asking

```
conseq run run-example.conseq
```

Run all possible rules, asking before each rule

```
conseq run run-example.conseq --confirm
```

Run possible combinations of artefacts for rank_scale_deps, and all downstream rules

```
conseq run run-example.conseq rank_scale_deps
```

Run only avana rank_scale_deps, and all downstream

```
conseq run run-example.conseq rank_scale_deps:dep.library=avana
```

Run avana and gecko rank_scale_deps, and all downstream

```
conseq run run-example.conseq rank_scale_deps:dep.library=avana rank_scale_deps:dep.library=gecko
```

Run correlation for the combination of avana and expression

```
conseq run run-example.conseq correlation:dep.library=avana,biomarker.category=expression --confirm
```


## Generate artefacts and rules diagram
* ```conseq altdot release_3_vbox.conseq > dag.dot```
* Open dag.dot in Graphviz
* Export to pdf if desired

