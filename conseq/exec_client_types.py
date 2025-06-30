from .xref import Resolver
from typing import Tuple, Dict, Optional, List, Any, Union, Protocol
from .types import BoundInput, PropsType
import json
import os
from dataclasses import dataclass

@dataclass
class ExecResult:
    """Result of executing a rule/command.
    
    Represents the outcome of running a rule execution, containing either
    success information (outputs) or failure information (error message).
    
    Attributes:
        failure_msg: Error message if execution failed, None if successful
        outputs: List of output artifacts produced by successful execution
        cache_key: Optional cache key for result caching/reuse
    """
    failure_msg: Optional[str]
    outputs: Optional[List[Dict[str, Any]]]
    cache_key: Optional[str] = None


class ResolveState:
    """Base class for tracking state during input resolution.
    
    Different execution clients may need to track different types of state
    while resolving inputs (e.g., files to upload, scripts to include).
    This base class provides the interface that subclasses should implement.
    """
    
    def add_script(self, script):
        """Add a script file to be included in the execution environment.
        
        Args:
            script: Path to script file to include
            
        Raises:
            Exception: This base implementation should not be called directly
        """
        raise Exception("Cannot call on base class")


class ProcLike(Protocol):
    """Protocol for process-like objects that can be polled and terminated.
    
    Defines the interface that process objects must implement to be compatible
    with the execution system. This allows for both real subprocess.Popen objects
    and mock/stub objects for testing or remote execution.
    """
    
    def poll(self) -> Optional[int]:
        """Check if process has completed.
        
        Returns:
            None if process is still running, exit code (int) if completed
        """
        ...
        
    def terminate(self):
        """Terminate the running process.
        
        Should send a termination signal to stop the process gracefully.
        """
        ...

class ClientExecution(Protocol):
    """Represents an active execution of a rule/command.
    
    Tracks the state and metadata of a running or completed execution,
    including the process, output files, and execution parameters.
    This class handles both local and remote executions.
    """

    def get_state_label(self) -> str:
        """Get a human-readable label describing the execution state.

        Returns:
            String label indicating the type/state of execution
        """
        ...

    def get_external_id(self) -> str:
        """Generate a serializable external reference for this execution.

        Creates a JSON string containing all the information needed to
        reattach to or identify this execution later.

        Returns:
            JSON string with execution metadata
        """
        ...

    # Path to the results.json file for this execution.
    results_path : str



class ExecClient:
    """Abstract base class for execution clients.
    
    Defines the interface that all execution clients must implement.
    Different clients handle local execution, remote delegation, etc.
    """
    
    def reattach(self, external_ref):
        """Reattach to an existing execution using its external reference.
        
        Args:
            external_ref: JSON string containing execution metadata
            
        Returns:
            ClientExecution object for the reattached execution
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError()

    def preprocess_inputs(
        self, resolver: Resolver, inputs: Tuple[BoundInput]
    ) -> Tuple[Dict[str, Dict[str, str]], ResolveState]:
        """Preprocess and resolve input artifacts for execution.
        
        Handles downloading files, resolving URLs, and preparing inputs
        for the execution environment.
        
        Args:
            resolver: Resolver for handling file URLs and references
            inputs: Bound input artifacts for the execution
            
        Returns:
            Tuple of (processed_inputs_dict, resolve_state)
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError()

    def exec_script(
        self,
        name: str,
        id: int,
        job_dir: str,
        run_stmts: List[str],
        outputs: Optional[List[Any]],
        capture_output: bool,
        prologue: str,
        desc_name: str,
        resolve_state: ResolveState,
        resources: Dict[str, float],
        watch_regex,
    ) -> ClientExecution:
        """Execute a script/command with the given parameters.
        
        Args:
            name: Name/identifier of the rule being executed
            id: Unique execution ID
            job_dir: Working directory for execution
            run_stmts: List of shell commands to execute
            outputs: Expected output artifacts (None if determined at runtime)
            capture_output: Whether to capture stdout/stderr to files
            prologue: Shell commands to run before main execution
            desc_name: Human-readable description
            resolve_state: State from input preprocessing
            resources: Resource requirements (CPU, memory, etc.)
            watch_regex: Optional regex pattern to watch for in logs
            
        Returns:
            ClientExecution object tracking the running execution
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError()

