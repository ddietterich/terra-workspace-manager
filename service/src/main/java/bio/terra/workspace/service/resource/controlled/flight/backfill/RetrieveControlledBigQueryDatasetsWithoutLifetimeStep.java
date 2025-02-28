package bio.terra.workspace.service.resource.controlled.flight.backfill;

import static bio.terra.workspace.service.workspace.flight.WorkspaceFlightMapKeys.ControlledResourceKeys.CONTROLLED_BIG_QUERY_DATASETS_WITHOUT_LIFETIME;

import bio.terra.stairway.FlightContext;
import bio.terra.stairway.Step;
import bio.terra.stairway.StepResult;
import bio.terra.stairway.exception.RetryException;
import bio.terra.workspace.db.ResourceDao;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.bqdataset.ControlledBigQueryDatasetResource;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

// TODO (PF-2269): Clean this up once the back-fill is done in all Terra environments.
public class RetrieveControlledBigQueryDatasetsWithoutLifetimeStep implements Step {
  private final ResourceDao resourceDao;

  public RetrieveControlledBigQueryDatasetsWithoutLifetimeStep(ResourceDao resourceDao) {
    this.resourceDao = resourceDao;
  }

  @Override
  public StepResult doStep(FlightContext context) throws InterruptedException, RetryException {
    List<ControlledBigQueryDatasetResource> controlledBigQueryDatasets =
        Optional.ofNullable(resourceDao.listControlledBigQueryDatasetsWithoutBothLifetime())
            .orElse(Collections.emptyList());

    context
        .getWorkingMap()
        .put(CONTROLLED_BIG_QUERY_DATASETS_WITHOUT_LIFETIME, controlledBigQueryDatasets);
    return StepResult.getStepResultSuccess();
  }

  @Override
  public StepResult undoStep(FlightContext context) throws InterruptedException {
    // READ-ONLY step. So do nothing here.
    return StepResult.getStepResultSuccess();
  }
}
