package bio.terra.workspace.service.resource.controlled.flight.clone.azure.container;

import bio.terra.stairway.FlightContext;
import bio.terra.stairway.Step;
import bio.terra.stairway.StepResult;
import bio.terra.stairway.exception.RetryException;
import bio.terra.workspace.common.utils.FlightUtils;
import bio.terra.workspace.service.resource.controlled.cloud.azure.storageContainer.ControlledAzureStorageContainerResource;
import bio.terra.workspace.service.resource.model.CloningInstructions;
import org.springframework.http.HttpStatus;

public class SetNoOpContainerCloneResponseStep implements Step {
  private final ControlledAzureStorageContainerResource sourceContainer;

  public SetNoOpContainerCloneResponseStep(
      ControlledAzureStorageContainerResource sourceContainer) {
    this.sourceContainer = sourceContainer;
  }

  @Override
  public StepResult doStep(FlightContext context) throws InterruptedException, RetryException {
    var noopResult =
        new ClonedAzureStorageContainer(
            CloningInstructions.COPY_NOTHING,
            sourceContainer.getWorkspaceId(),
            sourceContainer.getResourceId(),
            null);

    FlightUtils.setResponse(context, noopResult, HttpStatus.OK);
    return StepResult.getStepResultSuccess();
  }

  @Override
  public StepResult undoStep(FlightContext context) throws InterruptedException {
    return StepResult.getStepResultSuccess();
  }
}
