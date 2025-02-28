package bio.terra.workspace.service.resource.controlled.flight.backfill;

import static bio.terra.workspace.common.utils.FlightUtils.validateRequiredEntries;
import static bio.terra.workspace.service.crl.CrlService.getBigQueryDataset;
import static bio.terra.workspace.service.workspace.flight.WorkspaceFlightMapKeys.ControlledResourceKeys.CONTROLLED_BIG_QUERY_DATASETS_WITHOUT_LIFETIME;
import static bio.terra.workspace.service.workspace.flight.WorkspaceFlightMapKeys.ControlledResourceKeys.CONTROLLED_BIG_QUERY_DATASET_RESOURCE_ID_TO_PARTITION_LIFETIME_MAP;
import static bio.terra.workspace.service.workspace.flight.WorkspaceFlightMapKeys.ControlledResourceKeys.CONTROLLED_BIG_QUERY_DATASET_RESOURCE_ID_TO_TABLE_LIFETIME_MAP;
import static bio.terra.workspace.service.workspace.flight.WorkspaceFlightMapKeys.ControlledResourceKeys.CONTROLLED_RESOURCE_ID_TO_WORKSPACE_ID_MAP;

import bio.terra.stairway.FlightContext;
import bio.terra.stairway.Step;
import bio.terra.stairway.StepResult;
import bio.terra.stairway.exception.RetryException;
import bio.terra.workspace.service.crl.CrlService;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.bqdataset.BigQueryApiConversions;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.bqdataset.ControlledBigQueryDatasetResource;
import com.fasterxml.jackson.core.type.TypeReference;
import com.google.api.services.bigquery.model.Dataset;
import com.google.common.base.Preconditions;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.annotation.Nullable;
import kotlin.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO (PF-2269): Clean this up once the back-fill is done in all Terra environments.
public class RetrieveControlledBigQueryDatasetsLifetimeStep implements Step {
  private static final Logger logger =
      LoggerFactory.getLogger(RetrieveControlledBigQueryDatasetsLifetimeStep.class);
  private final CrlService crlService;

  public RetrieveControlledBigQueryDatasetsLifetimeStep(CrlService crlService) {
    this.crlService = crlService;
  }

  @Override
  public StepResult doStep(FlightContext context) throws InterruptedException, RetryException {
    validateRequiredEntries(
        context.getWorkingMap(), CONTROLLED_BIG_QUERY_DATASETS_WITHOUT_LIFETIME);
    List<ControlledBigQueryDatasetResource> controlledBigQueryDatasets =
        Preconditions.checkNotNull(
            context
                .getWorkingMap()
                .get(CONTROLLED_BIG_QUERY_DATASETS_WITHOUT_LIFETIME, new TypeReference<>() {}));
    Map<UUID, String> resourceIdToDefaultTableLifetimeMap = new HashMap<>();
    Map<UUID, String> resourceIdToDefaultPartitionLifetimeMap = new HashMap<>();
    Map<UUID, String> resourceIdToWorkspaceIdMap = new HashMap<>();

    for (ControlledBigQueryDatasetResource resource : controlledBigQueryDatasets) {
      logger.info(
          "Getting default table lifetime and partition life for resource (BigQuery dataset) {} in workspace {}",
          resource.getResourceId(),
          resource.getWorkspaceId());

      populateMapsWithResourceIdKey(
          resourceIdToDefaultTableLifetimeMap,
          resourceIdToDefaultPartitionLifetimeMap,
          resourceIdToWorkspaceIdMap,
          resource);
    }
    context
        .getWorkingMap()
        .put(
            CONTROLLED_BIG_QUERY_DATASET_RESOURCE_ID_TO_TABLE_LIFETIME_MAP,
            resourceIdToDefaultTableLifetimeMap);
    context
        .getWorkingMap()
        .put(
            CONTROLLED_BIG_QUERY_DATASET_RESOURCE_ID_TO_PARTITION_LIFETIME_MAP,
            resourceIdToDefaultPartitionLifetimeMap);
    context
        .getWorkingMap()
        .put(CONTROLLED_RESOURCE_ID_TO_WORKSPACE_ID_MAP, resourceIdToWorkspaceIdMap);
    return StepResult.getStepResultSuccess();
  }

  /**
   * @param resourceIdToDefaultTableLifetimeMap: maps ids to table lifetime.
   * @param resourceIdToDefaultPartitionLifetimeMap: maps ids to partition lifetime.
   * @param resourceIdToWorkspaceIdMap: maps ids to workspace.
   * @param resource: resource mapped in the previous three maps.
   */
  private void populateMapsWithResourceIdKey(
      Map<UUID, String> resourceIdToDefaultTableLifetimeMap,
      Map<UUID, String> resourceIdToDefaultPartitionLifetimeMap,
      Map<UUID, String> resourceIdToWorkspaceIdMap,
      ControlledBigQueryDatasetResource resource) {
    UUID resourceId = resource.getResourceId();
    Pair<Long, Long> tableAndPartitionLifetime =
        getBqDatasetDefaultTableLifetimeAndPartitionLifetime(resource);

    resourceIdToWorkspaceIdMap.put(resourceId, resource.getWorkspaceId().toString());
    if (tableAndPartitionLifetime != null) {
      Long tableLifetime = tableAndPartitionLifetime.getFirst();
      Long partitionLifetime = tableAndPartitionLifetime.getSecond();

      if (tableLifetime != null) {
        resourceIdToDefaultTableLifetimeMap.put(resourceId, tableLifetime.toString());
      }
      if (partitionLifetime != null) {
        resourceIdToDefaultPartitionLifetimeMap.put(resourceId, partitionLifetime.toString());
      }
    }
  }

  /**
   * @return Pair with lifetimes. First coordinate is table lifetime; second is partition lifetime.
   */
  @Nullable
  private Pair<Long, Long> getBqDatasetDefaultTableLifetimeAndPartitionLifetime(
      ControlledBigQueryDatasetResource resource) {
    Dataset dataset = getBqDataset(resource);
    if (dataset != null) {
      return new Pair<>(
          BigQueryApiConversions.fromBqExpirationTime(dataset.getDefaultTableExpirationMs()),
          BigQueryApiConversions.fromBqExpirationTime(dataset.getDefaultPartitionExpirationMs()));
    }
    return null;
  }

  @Nullable
  private Dataset getBqDataset(ControlledBigQueryDatasetResource resource) {
    try {
      return getBigQueryDataset(
          crlService.createWsmSaBigQueryCow(), resource.getProjectId(), resource.getDatasetName());
    } catch (IOException e) {
      logger.error(
          "Failed to get dataset with resource ID {} in workspace {}: {}",
          resource.getResourceId(),
          resource.getWorkspaceId(),
          e.getMessage());
      return null;
    }
  }

  @Override
  public StepResult undoStep(FlightContext context) throws InterruptedException {
    // READ-ONLY step, do nothing here.
    return StepResult.getStepResultSuccess();
  }
}
