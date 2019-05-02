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

## Concepts

Artifacts: A set of key value pairs that model a piece of data that will either be consumed by rules or was generated by executing a rule. 

Values: The values in the key/value pairs artifacts are strings or file references. The syntax `{'$filename': path}` is used to denote values which are file references.

Rules: A rule has a set of inputs which define which artifacts it consumes, and "run" statements to execute when such artifacts are availible.

Executions: An execution is the application of a rule on a specific set of artifacts. The rule is essentially a template, and the execution is a combination of a rule and the inputs.

## Statements allowed in conseq files

## Define a variable: "let ..."

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

The variable **SCRIPT_DIR** is automatically defined at startup and often is used in conseq rules. This variable contains
 the absolute path to the directory containing the conseq script being run. 
 
This is frequently needed as each task runs in its own unique directory. This variable is useful
 for generating relative paths to files which are not artifacts. You can prefix your path with this 
  variable and providing a path relative to the conseq config being executed.

For example, assuming "process.py" is in the same directory as the conseq file, you can 
execute that script from a `run` statement such as:  `run 'python {{ SCRIPT_DIR }}/process.py'`

Additional variables automatically defined at start up:

* **DL_CACHE_DIR** The directory that remote files are cached in after downloading.
* **PROLOGUE** Text which is preprended to each shell script that's generated for executing a rule.  Useful for configuring the environment before the command runs.
* **S3_STAGING_URL** Location where files will be staged and then later pulled from when executing remote jobs
* **AWS_ACCESS_KEY_ID** AWS key ID used for reading/writing to S3
* **AWS_SECRET_ACCESS_KEY** AWS secret used for reading/writing to S3
* **WORKING_DIR** The local dir where scripts are written to and tasks are run from


## Add an artifact: "add-if-missing ..."

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

## Define a rule: "rule ..."

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

`run "X" with "Y"`

Write "Y" to a temp file and execute the command "X *temp_filename*". 

For example to write an inline R script you could write:

`run "Rscript" with "print('hello')"`

### Adding artifacts to repo after task completion

Most commonly we specify an "outputs:" section on the rule which lists the key/value pairs on the artifacts which 
should be published back to the repo upon successful completion.

We can use "$filename" if we want to publish a path to a file that we've emitted. 

The reason filenames are handled differently from generic strings is for the following reasons: 
 1. We can specify a filename as a local path within a task, and if another task uses that filename, it will use the full path to avoid issues due to the downstream task running in a different directory.
 2. If a downstream job uses an artifact with a $filename reference, it will automatically make sure the file is pushed to cloud storage before running the task, and localizing it to the remote host before execution.
 3. When publishing an artifact to cloud storage, it will upload any $filename references and replace them with $file_url references. 

As part of running a rule, we should publish the results back to conseq.   For simple cases, we can include a "outputs" clause where we can list a static list of artifacts which will be published if and only if all run statements execute successfully.

The values of the key/value pairs of artifacts are treated as jinja templates and expanded. They have access to the "inputs", "task" and "config" dictionaries at the time of expansion. Most often this is used to copy fields from an input onto the output artifacts.

Example:
```
rule simple:
    inputs: in = {'type': 'person'}
    outputs: 
```

Alternatively, if the artifacts can't be determined ahead of time, we can have one of our run statements write a "results.json" file with the artifacts in it. Conseq will attempt to part that file and read the artifacts if the task completes successfully.

<a name="conseq-command-line-reference"/>

# Command Line Reference

You can get help on all conseq commands by running `conseq --help`

## List artefacts

List all artifacts

```
conseq ls
```

List artifacts where type is 'dep-matrix'

```
conseq ls type=dep-matrix
```

List artifacts where type is 'dep-matrix' and library is 'avana'

```
conseq ls type=dep-matrix library=avana
```

## Remove artefacts

Remove all artifacts

```
conseq rm
```

Remove artifacts where type is 'dep-matrix'
```
conseq rm type=dep-matrix
```

Remove artifacts where type is 'dep-matrix' and library is 'avana'
```
conseq rm type=dep-matrix library=avana
```

To remove all artefacts AND history of executions, delete the ```state/``` directory. This will reset conseq to a clean slate.


## Run rules

Run all possible rules, without asking

```
conseq run run-example.conseq
```

Run all possible rules, asking before each rule

```
conseq run run-example.conseq --confirm
```

Run possible combinations of artefacts for rank_scale_deps, and all downstream rules. This forces running the rule, even if it has been run before.

```
conseq run run-example.conseq rank_scale_deps
```

Run only executions of rank_scale_deps where the "dep" input is bound to an artifact which has "library" set to "avana". (Will also run downstream rules)

```
conseq run run-example.conseq rank_scale_deps:dep.library=avana
```

Similar to above, but each artifact filter is ORed. (ie: the below filters tasks where the "dep" input is bound to an artifact which has "library" set to "avana" or "gecko")

```
conseq run run-example.conseq rank_scale_deps:dep.library=avana rank_scale_deps:dep.library=gecko
```

Run correlation for the combination of avana and expression

```
conseq run run-example.conseq correlation:dep.library=avana,biomarker.category=expression
```


## Generate artefacts and rules diagram
* ```conseq altdot release_3_vbox.conseq > dag.dot```
* Open dag.dot in Graphviz (or execute `dot dag.dot -Tpng -o dag.png`)

