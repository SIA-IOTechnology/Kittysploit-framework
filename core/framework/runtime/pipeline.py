#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Dict, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
import time
import threading

from core.framework.base_module import BaseModule
from .events import EventBus, EventType
from .extension_contract import MiddlewareExtension


class PipelineStepType(Enum):
    """Types d'étapes de pipeline"""
    MODULE = "module"
    WORKFLOW = "workflow"
    AUTOMATION = "automation"
    CONDITION = "condition"
    TRANSFORM = "transform"


@dataclass
class PipelineStep:
    """Étape d'un pipeline"""
    step_id: str
    step_type: PipelineStepType
    name: str
    description: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[Callable] = None
    on_success: Optional[str] = None  # ID de l'étape suivante en cas de succès
    on_failure: Optional[str] = None   # ID de l'étape suivante en cas d'échec
    timeout: Optional[float] = None
    retry_count: int = 0
    retry_delay: float = 1.0
    
    # Résultats d'exécution
    executed: bool = False
    result: Any = None
    error: Optional[str] = None
    execution_time: float = 0.0


@dataclass
class PipelineContext:
    """Contexte d'exécution d'un pipeline"""
    pipeline_id: str
    start_time: float = field(default_factory=time.time)
    data: Dict[str, Any] = field(default_factory=dict)
    results: Dict[str, Any] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    current_step: Optional[str] = None
    status: str = "pending"  # pending, running, completed, failed, cancelled


class Pipeline:
    """
    Pipeline - Composition de modules, workflows et automation
    
    Un pipeline permet de chaîner plusieurs étapes avec gestion des erreurs,
    conditions et transformations de données.
    """
    
    def __init__(
        self,
        name: str,
        description: str = "",
        event_bus: Optional[EventBus] = None
    ):
        self.name = name
        self.description = description
        self.steps: Dict[str, PipelineStep] = {}
        self.start_step: Optional[str] = None
        self.middlewares: List[MiddlewareExtension] = []
        self.event_bus = event_bus
        self.lock = threading.Lock()
    
    def add_step(
        self,
        step_id: str,
        step_type: PipelineStepType,
        name: str,
        config: Dict[str, Any] = None,
        condition: Optional[Callable] = None,
        on_success: Optional[str] = None,
        on_failure: Optional[str] = None,
        timeout: Optional[float] = None,
        retry_count: int = 0
    ) -> PipelineStep:
        """Ajoute une étape au pipeline"""
        step = PipelineStep(
            step_id=step_id,
            step_type=step_type,
            name=name,
            config=config or {},
            condition=condition,
            on_success=on_success,
            on_failure=on_failure,
            timeout=timeout,
            retry_count=retry_count
        )
        
        self.steps[step_id] = step
        
        # Définir comme étape de départ si c'est la première
        if self.start_step is None:
            self.start_step = step_id
        
        return step
    
    def add_middleware(self, middleware: MiddlewareExtension):
        """Ajoute un middleware au pipeline"""
        self.middlewares.append(middleware)
        # Trier par ordre
        self.middlewares.sort(key=lambda m: m.order)
    
    def set_start_step(self, step_id: str):
        """Définit l'étape de départ"""
        if step_id not in self.steps:
            raise ValueError(f"Step {step_id} not found in pipeline")
        self.start_step = step_id
    
    def execute(
        self,
        initial_data: Dict[str, Any] = None,
        module_loader: Optional[Callable] = None,
        workflow_loader: Optional[Callable] = None
    ) -> PipelineContext:
        """
        Exécute le pipeline
        
        Args:
            initial_data: Données initiales pour le pipeline
            module_loader: Fonction pour charger les modules
            workflow_loader: Fonction pour charger les workflows
            
        Returns:
            PipelineContext: Contexte d'exécution avec résultats
        """
        pipeline_id = f"{self.name}_{int(time.time() * 1000)}"
        context = PipelineContext(
            pipeline_id=pipeline_id,
            data=initial_data or {}
        )
        
        if self.event_bus:
            self.event_bus.publish(
                EventType.PIPELINE_STARTED,
                {"pipeline": self.name, "pipeline_id": pipeline_id},
                source="pipeline"
            )
        
        context.status = "running"
        
        try:
            current_step_id = self.start_step
            if not current_step_id:
                raise ValueError("No start step defined")
            
            while current_step_id:
                step = self.steps.get(current_step_id)
                if not step:
                    raise ValueError(f"Step {current_step_id} not found")
                
                context.current_step = current_step_id
                
                # Vérifier la condition
                if step.condition and not step.condition(context):
                    # Passer à l'étape suivante
                    current_step_id = step.on_success
                    continue
                
                # Exécuter l'étape
                step_start_time = time.time()
                
                if self.event_bus:
                    self.event_bus.publish(
                        EventType.PIPELINE_STEP_STARTED,
                        {
                            "pipeline": self.name,
                            "pipeline_id": pipeline_id,
                            "step": step.name,
                            "step_id": step_id
                        },
                        source="pipeline"
                    )
                
                success = False
                error = None
                
                # Appliquer les middlewares
                request = {
                    "step": step,
                    "context": context,
                    "data": context.data
                }
                
                def execute_step():
                    return self._execute_step(
                        step,
                        context,
                        module_loader,
                        workflow_loader
                    )
                
                # Chaîner les middlewares
                handler = execute_step
                for middleware in reversed(self.middlewares):
                    if middleware.is_enabled():
                        current_handler = handler
                        handler = lambda m=middleware, h=current_handler: m.process(
                            request.copy(),
                            h
                        )
                
                try:
                    result = handler()
                    success = result is not False and result is not None
                    step.result = result
                except Exception as e:
                    success = False
                    error = str(e)
                    step.error = error
                    context.errors[step.step_id] = error
                
                step.executed = True
                step.execution_time = time.time() - step_start_time
                
                if self.event_bus:
                    event_type = EventType.PIPELINE_STEP_COMPLETED if success else EventType.PIPELINE_STEP_FAILED
                    self.event_bus.publish(
                        event_type,
                        {
                            "pipeline": self.name,
                            "pipeline_id": pipeline_id,
                            "step": step.name,
                            "step_id": step.step_id,
                            "success": success,
                            "error": error
                        },
                        source="pipeline"
                    )
                
                # Stocker le résultat
                context.results[step.step_id] = step.result
                
                # Déterminer la prochaine étape
                if success:
                    current_step_id = step.on_success
                else:
                    # Retry si configuré
                    if step.retry_count > 0 and not step.executed:
                        step.retry_count -= 1
                        time.sleep(step.retry_delay)
                        continue
                    current_step_id = step.on_failure
                
                # Arrêter si pas d'étape suivante
                if not current_step_id:
                    break
            
            context.status = "completed"
            
            if self.event_bus:
                self.event_bus.publish(
                    EventType.PIPELINE_COMPLETED,
                    {
                        "pipeline": self.name,
                        "pipeline_id": pipeline_id,
                        "duration": time.time() - context.start_time
                    },
                    source="pipeline"
                )
        
        except Exception as e:
            context.status = "failed"
            context.errors["pipeline"] = str(e)
            
            if self.event_bus:
                self.event_bus.publish(
                    EventType.PIPELINE_FAILED,
                    {
                        "pipeline": self.name,
                        "pipeline_id": pipeline_id,
                        "error": str(e)
                    },
                    source="pipeline"
                )
        
        return context
    
    def _execute_step(
        self,
        step: PipelineStep,
        context: PipelineContext,
        module_loader: Optional[Callable],
        workflow_loader: Optional[Callable]
    ) -> Any:
        """Exécute une étape du pipeline"""
        if step.step_type == PipelineStepType.MODULE:
            return self._execute_module_step(step, context, module_loader)
        elif step.step_type == PipelineStepType.WORKFLOW:
            return self._execute_workflow_step(step, context, workflow_loader)
        elif step.step_type == PipelineStepType.CONDITION:
            return self._execute_condition_step(step, context)
        elif step.step_type == PipelineStepType.TRANSFORM:
            return self._execute_transform_step(step, context)
        else:
            raise ValueError(f"Unknown step type: {step.step_type}")
    
    def _execute_module_step(
        self,
        step: PipelineStep,
        context: PipelineContext,
        module_loader: Optional[Callable]
    ) -> Any:
        """Exécute une étape de module"""
        if not module_loader:
            raise ValueError("Module loader not provided")
        
        module_path = step.config.get("module_path")
        if not module_path:
            raise ValueError("module_path not specified in step config")
        
        # Charger le module
        module = module_loader(module_path)
        if not module:
            raise ValueError(f"Failed to load module: {module_path}")
        
        # Configurer les options du module depuis le contexte
        options = step.config.get("options", {})
        for key, value in options.items():
            # Support pour les références au contexte: ${context.key}
            if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                context_key = value[2:-1]
                value = context.data.get(context_key, value)
            
            if hasattr(module, key):
                module.set_option(key, value)
        
        # Exécuter le module
        return module.run()
    
    def _execute_workflow_step(
        self,
        step: PipelineStep,
        context: PipelineContext,
        workflow_loader: Optional[Callable]
    ) -> Any:
        """Exécute une étape de workflow"""
        if not workflow_loader:
            raise ValueError("Workflow loader not provided")
        
        workflow_path = step.config.get("workflow_path")
        if not workflow_path:
            raise ValueError("workflow_path not specified in step config")
        
        # Charger le workflow
        workflow = workflow_loader(workflow_path)
        if not workflow:
            raise ValueError(f"Failed to load workflow: {workflow_path}")
        
        # Exécuter le workflow
        return workflow.run()
    
    def _execute_condition_step(
        self,
        step: PipelineStep,
        context: PipelineContext
    ) -> bool:
        """Exécute une étape de condition"""
        condition_func = step.config.get("condition_func")
        if not condition_func or not callable(condition_func):
            raise ValueError("condition_func not specified or not callable")
        
        return condition_func(context)
    
    def _execute_transform_step(
        self,
        step: PipelineStep,
        context: PipelineContext
    ) -> Any:
        """Exécute une étape de transformation"""
        transform_func = step.config.get("transform_func")
        if not transform_func or not callable(transform_func):
            raise ValueError("transform_func not specified or not callable")
        
        result = transform_func(context.data)
        # Mettre à jour le contexte avec le résultat
        output_key = step.config.get("output_key", "transformed_data")
        context.data[output_key] = result
        return result

