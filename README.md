##### Table of Contents  
* [Conseq Config Reference](#conseq-config-reference)
* [Command Line Reference](#command-line-reference)

# Conseq 
(Pronounced "con-SIK" as in "consequence")

Conseq is a tool for running sequences of transformations or other operations.

More on the motivation and details seen this slide deck: https://docs.google.com/a/broadinstitute.com/presentation/d/1LsRymTEKmqDxACDnMIx1z_Y2dQtY7TNpb5PAFyK0OQM/edit?usp=sharing
or this poster https://drive.google.com/file/d/1FF8ESVbo_LXs4BBfEGAgkbq77ABXyzKu/view?usp=sharing

<a name="conseq-config-reference"/>

## Installation

### Clone and install the repo
- clone the repo
- run `python setup.py develop`
- verify successful install by running `conseq --help`

### Obtain AWS keys
From https://console.aws.amazon.com/, in the toolbar under your_name@your_project, select security credentials. Generate access keys under "Access keys for CLI, SDK, & API access".

### Configure conseq
Create a `.conseq` file in your home directory as follows.

```
let AWS_ACCESS_KEY_ID = "<insert access key id>"
let AWS_SECRET_ACCESS_KEY = "<insert access key>"
```

If running the depmap portal pipeline, the following may also be required

```
let TAIGA_URL = "http://taiga.broadinstitute.org"
let DSUB_PATH = "<path to dsub installation>"
```


# Conseq Config Reference

A conseq config file consists of "add-if-missing" artifact definitions, variables 
and rules.  

## Concepts

Artifacts: A set of key value pairs that model a piece of data that will either be consumed by rules or was generated by executing a rule. 

Values: The values in the key/value pairs artifacts are strings or file references. 
The syntax `{'$filename': path}` is used to denote values which are file references.

Rules: A rule has a set of inputs which define which artifacts it consumes, and "run" statements to execute when such artifacts are availible.

Executions: An execution is the application of a rule on a specific set of artifacts. The rule is essentially a template, and the execution is a combination of a rule and the inputs.

## Overview

Conseq is a tool used to execute a series of scripts, based on the dependencies that 
are declared between them.

Conseq can be thought of as a way to run a large "pipeline" where that pipeline is a 
directed acyclic graph. 

Rules are declared which explain what types are artifacts the rule depends on and 
uses for input. Upon executing a rule on some inputs, new output artifacts are created,
resulting in downstream rules to execute.

Each artifact is either created via an "add-if-missing" statement, or else created 
from a rule execution.

Artifacts can be uniquely identified by their "key" which is computed from all the "simple" key value pairs.
For example, the artifact 
```{"type": "fruit", "name": "banana", "filename": {"$file": "r2/stats.csv"}}``` has a key like "type=fruit,name=banana".

An artifact```{"type": "fruit", "name": "banana", "filename": {"$file": "r5/stats.csv"}}``` also has key the "type=fruit,name=banana".

### Rule reconcilation

To accomodate development and the nature of the pipeline changing, when the `run` command 
starts conseq reconciles the contents of the artifact database with the contents of the 
conseq script.

Any artifacts which were previously added via 'add-if-missing' no longer are added.
Any rules which no longer exist are deleted from the database.
If a rule execution is deleted, all downstream artifacts and rule executions are also deleted.



## Statements allowed in conseq files

### Define a variable: "let ..."

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
 the absolute path to the directory containing the conseq script being run. (Note, if conseq files are included from different directories, this variable doesn't change. It always points to the directory of the top level conseq file) 
 
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


### Add an artifact: "add-if-missing ..."

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

### Define a rule: "rule ..."

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

### References to files

If a rule uses external scripts it's good to list those via the "filename"
annotation in the inputs. This has two advantages:
 1. If the job runs on a remote node, the file will automatically be copied to the remote node for you.
 2. If the script changes, it will automaticly detect this rule needs to be rerun.

Example:

Imagine we have a bash script named "printdate.sh". We can write a rule
which will run that script by creating a conseq file named
`fileref-example.conseq` containing:

```
rule runscript:
    inputs: script=filename('printdate.sh')
    outputs: {"type": "runscript-done"}
    run "bash {{inputs.script.filename}}"    
```

now `conseq run fileref-example.conseq` will execute printdate.sh. If we try
to run `conseq run fileref-example.conseq` a second time, nothing will
happen because it knows it's already run that rule.

However, if we change `printdate.sh` and run `conseq run fileref-example.conseq`
once more, it will get rid of the existing artifact from that rule and
re-run the "runscript" rule.

It's worth noting that jobs that are run on a remote node first have their input 
artifact's files copied to the node before their job starts. When this copy is 
performed each file is given a unique filename. If you need to control 
the name of the file, you can include the parameter `copy_to=...` on the
filename reference.

For example, in the following example, we'd like to use a python file. 
However, in order to import the file, we need to make sure the file is 
named correctly. We can accomplish that by providing `copy_to` and this 
will ensure the python file is copied into the job's working directory
before it starts.

```
rule runscript:
    inputs: hdf5utils=filename('hdf5utils.py', copy_to='hdf5utils.py')
    outputs: {"type": "runscript-done"}
    run "python" with """
       import hdf5utils
       hdf5utils.transform_all()
    """    
```

<a name="conseq-command-line-reference"/>

# Command Line Reference

You can get help on all conseq commands by running `conseq --help`

## List artifacts

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

These tables get very wide, so you can also ask it to only show you select columns

```
conseq ls type=dep-matrix columns=library,figshare_id
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

## Debugging why rules didn't run

For rules which take lots of inputs, it can be painful to track down 
why a rule didn't run. The issue could be with _any_ of the inputs.

For this, you can use the `debugrule` command to give you a starting point.

For example:

```
conseq debugrun run_test.conseq assemble_ensemble_genomic_feature_set   (depmap)
opening state/db.sqlite3
2021-04-16 16:48:03,601 INFO: 1 matches for <ForEach expression where {'type': 'pred-biomarker-matrix-csv', 'category': 'expression'}>
2021-04-16 16:48:03,604 INFO: 1 matches for <ForEach ssgsea where {'type': 'pred-biomarker-matrix-csv', 'category': 'ssgsea'}>
2021-04-16 16:48:03,607 INFO: 1 matches for <ForEach cn where {'type': 'pred-biomarker-matrix-csv', 'category': 'copy-number-relative'}>
2021-04-16 16:48:03,609 INFO: 1 matches for <ForEach damaging_mutations where {'type': 'pred-biomarker-matrix-csv', 'category': 'mutations-damaging'}>
2021-04-16 16:48:03,611 INFO: 1 matches for <ForEach nonconserving_mutations where {'type': 'pred-biomarker-matrix-csv', 'category': 'mutations-nonconserving'}>
2021-04-16 16:48:03,614 INFO: 1 matches for <ForEach hotspot_mutations where {'type': 'pred-biomarker-matrix-csv', 'category': 'mutations-hotspot'}>
2021-04-16 16:48:03,616 INFO: 1 matches for <ForEach fusions where {'type': 'pred-biomarker-matrix-csv', 'category': 'fusions'}>
2021-04-16 16:48:03,619 INFO: 1 matches for <ForEach lineage where {'type': 'pred-biomarker-matrix-csv', 'category': 'context'}>
2021-04-16 16:48:03,621 INFO: 16 matches for <ForEach confounders where {'type': 'pred-biomarker-matrix-csv'}>
2021-04-16 16:48:03,623 INFO: 0 matches for <ForEach match_related where {'type': 'match-related-matrix-csv'}>
2021-04-16 16:48:03,625 INFO: 3 matches for <ForEach dep where {'type': 'pred-dep-matrix-csv'}>
2021-04-16 16:48:03,627 INFO: 5 matches for <ForEach dep_prob where {'type': 'pred-dep-prob-matrix-ftr'}>
2021-04-16 16:48:03,629 INFO: 5 matches for <ForEach model_config where {'type': 'ensemble-model-config'}>
2021-04-16 16:48:03,673 INFO: 0 matches for entire rule
```

The `debugrule` command will run each input's query independently and report the number of matches found. Any queries that result in 0 
artifacts found will prevent the rule from running. If each query reports at 
least one artifact, the issue must lay with one of the **joins** across queries.

## Copying artifact database between machines

We may want to make a copy of a big pipeline run, and make some changes. For this we 
can "export" the artifacts to a file and then import them on a different machine.

To generate the export:

```
$ conseq export test-run.conseq export.conseq
```

This will not only write all the artifacts (key value pairs) and rule execution 
history to export.conseq, it will also upload all files referenced by those
artifacts into cloud storage. Instead of local paths, the exported artifacts 
will have paths which point out to cloud storage.

You now can run this with a new working directory and import it:
```
$ mkdir work
$ cd work
$ conseq run ../export.conseq
```

Running this export will create all the artifacts but not download any files. 
However, the imported artifacts include cloud paths from which conseq will download  
data before executing rules that consume that artifact.

## Viewing outputs from an imported run

Since importing an export from a different machine does not download the
referenced files, you cannot immediatly view outputs from the run. While
the files will automatically be downloaded if you run a rule which depends
on the files, that's not helpful when you're manually looking at outputs.

For this case, you can manually request conseq download all the files 
associated with a set of artifacts. You identify the artifacts using the
same query syntax as `conseq ls`:

```
conseq localize run_test.conseq type=matrix-csv
```

Any files associated with artifacts of type `matrix-csv` will be downloaded.

To find out where the files were downloaded, you can now use `ls` to 
view the property which contained the file reference:

```
conseq ls type=pred-dep-matrix-csv --columns filename
```


## Inspecting artifacts after running jobs

For large pipelines, it can be difficult to visualize what all got run. To browse
all artifacts and/or browse the provenance of any artifact you can generate
an html report which summarizes all this:

```
$ conseq report html
```

The above command will create a directory named "html" and you can 
open `html/index.html` to browse the report.

## Generate artefacts and rules diagram
* ```conseq altdot release_3_vbox.conseq > dag.dot```
* Open dag.dot in Graphviz (or execute `dot dag.dot -Tpng -o dag.png`)

## Cleaning up space from past runs

Whenever rules or artifacts manually added via `add-if-missing` change, 
they are deleted from the artifact repository along with all downstream 
rule executions and artifacts. This cleans up the artifacts, however, 
the `state` directory contains all of the output files from those executions
and these files are not automatically cleaned up.

You can tell conseq to delete any directories which are no longer referenced
by any artifacts by running:

```
$ conseq gc
```

## Remote execution

You can define custom "execution profiles" which tell conseq how to launch
jobs on remote machines.

You need only configure:
1. a template for the command used to submit the job and get a job ID conseq
can use to track the job.
2. a template for the command used to poll the job and ask whether the job has completed or not.   

Here's a configuration for submitting via dsub:

```
exec-profile dsub-tda-img {
 "type": "async-delegate",
 "label": "dsub-runner-img",
 "resources": { "slots": "5" },
 "HELPER_PATH": "python3 /helper.py",
 "COMMAND_TEMPLATE": """{{config.DSUB_PATH}}/dsub \
     --project broad-achilles \
     --zones "us-east1*" \
     --logging gs://conseq-logging/logging/{JOB} \
     --image us.gcr.io/broad-achilles/depmap-pipeline-tda:v4 \
     --env AWS_ACCESS_KEY_ID={{config.AWS_ACCESS_KEY_ID}} \
     --env AWS_SECRET_ACCESS_KEY={{config.AWS_SECRET_ACCESS_KEY}} \
     --min-ram 10 \
     --command '{COMMAND}'""", # AWS keys needed for boto
 "CHECK_COMMAND_TEMPLATE": """{{config.DSUB_PATH}}/dstat \
     --project broad-achilles \
     --jobs {job_id} \
     --status 'RUNNING'""",
 "IS_RUNNING_PATTERN": "Status", # Really anything because we are only
                                 # listing running jobs. Just make sure
                                 # there's some output
 "TERMINATE_CMD_TEMPLATE": "{{config.DSUB_PATH}}/ddel --project broad-achilles --jobs {job_id}",
 "JOB_ID_PATTERN": "{{ config.DSUB_JOB_ID_PATTERN }}"
}
```

Configuration for running via docker:

```
exec-profile async-docker-tda-img {
  "type": "async-delegate",
  "label": "ddddd",
  "resources": { "slots": "1" },
  "HELPER_PATH": "python3 /helper.py",
  "COMMAND_TEMPLATE": """docker run \
      --rm \
      -d \
      -e AWS_ACCESS_KEY_ID={{config.AWS_ACCESS_KEY_ID}} \
      -e AWS_SECRET_ACCESS_KEY={{config.AWS_SECRET_ACCESS_KEY}} \
      us.gcr.io/broad-achilles/depmap-pipeline-tda:v4 \
      {COMMAND}""", # AWS keys needed for boto
  "JOB_ID_PATTERN": """(\S+)""",
  "CHECK_COMMAND_TEMPLATE": "docker ps -f id={job_id} --format running",
  "IS_RUNNING_PATTERN": "running", # this is the only output if the job is running
  "TERMINATE_CMD_TEMPLATE": "docker kill {job_id}"
}
```