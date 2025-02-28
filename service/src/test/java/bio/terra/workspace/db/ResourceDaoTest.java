package bio.terra.workspace.db;

import static bio.terra.workspace.common.fixtures.ControlledResourceFixtures.DEFAULT_CREATED_BIG_QUERY_PARTITION_LIFETIME;
import static bio.terra.workspace.common.fixtures.ControlledResourceFixtures.DEFAULT_CREATED_BIG_QUERY_TABLE_LIFETIME;
import static bio.terra.workspace.common.fixtures.ControlledResourceFixtures.DEFAULT_RESOURCE_PROPERTIES;
import static bio.terra.workspace.common.fixtures.ControlledResourceFixtures.makeDefaultControlledResourceFieldsBuilder;
import static bio.terra.workspace.common.fixtures.ControlledResourceFixtures.makeNotebookCommonFieldsBuilder;
import static bio.terra.workspace.common.utils.MockMvcUtils.DEFAULT_USER_EMAIL;
import static bio.terra.workspace.common.utils.MockMvcUtils.DEFAULT_USER_SUBJECT_ID;
import static bio.terra.workspace.unit.WorkspaceUnitTestUtils.createWorkspaceWithGcpContext;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import bio.terra.workspace.common.BaseUnitTest;
import bio.terra.workspace.common.fixtures.ControlledResourceFixtures;
import bio.terra.workspace.common.logging.model.ActivityLogChangedTarget;
import bio.terra.workspace.common.utils.TestUtils;
import bio.terra.workspace.db.model.DbResource;
import bio.terra.workspace.db.model.DbWorkspaceActivityLog;
import bio.terra.workspace.service.resource.controlled.cloud.any.flexibleresource.ControlledFlexibleResource;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.ainotebook.ControlledAiNotebookInstanceResource;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.bqdataset.ControlledBigQueryDatasetResource;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.gcsbucket.ControlledGcsBucketResource;
import bio.terra.workspace.service.resource.controlled.model.AccessScopeType;
import bio.terra.workspace.service.resource.controlled.model.ControlledResource;
import bio.terra.workspace.service.resource.controlled.model.ControlledResourceFields;
import bio.terra.workspace.service.resource.controlled.model.ManagedByType;
import bio.terra.workspace.service.resource.controlled.model.PrivateResourceState;
import bio.terra.workspace.service.resource.exception.DuplicateResourceException;
import bio.terra.workspace.service.resource.exception.ResourceNotFoundException;
import bio.terra.workspace.service.resource.model.CloningInstructions;
import bio.terra.workspace.service.resource.model.StewardshipType;
import bio.terra.workspace.service.resource.model.WsmResourceType;
import bio.terra.workspace.service.workspace.GcpCloudContextService;
import bio.terra.workspace.service.workspace.exceptions.MissingRequiredFieldsException;
import bio.terra.workspace.service.workspace.model.CloudPlatform;
import bio.terra.workspace.service.workspace.model.OperationType;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.beans.factory.annotation.Autowired;

@TestInstance(Lifecycle.PER_CLASS)
public class ResourceDaoTest extends BaseUnitTest {
  @Autowired ResourceDao resourceDao;
  @Autowired WorkspaceDao workspaceDao;
  @Autowired GcpCloudContextService gcpCloudContextService;
  @Autowired WorkspaceActivityLogDao activityLogDao;
  @Autowired RawDaoTestFixture rawDaoTestFixture;

  private UUID workspaceUuid;

  @BeforeAll
  public void setUp() {
    workspaceUuid = createWorkspaceWithGcpContext(workspaceDao);
  }

  @AfterAll
  public void cleanUp() {
    workspaceDao.deleteCloudContext(workspaceUuid, CloudPlatform.GCP);
    workspaceDao.deleteWorkspace(workspaceUuid);
  }

  @Test
  public void createGetControlledGcsBucket_beforeLogIsWrite_lastUpdatedDateEqualsCreatedDate() {
    ControlledGcsBucketResource resource =
        ControlledResourceFixtures.makeDefaultControlledGcsBucketBuilder(workspaceUuid).build();
    ControlledResourceFixtures.insertControlledResourceRow(resourceDao, resource);

    var getResource = resourceDao.getResource(resource.getWorkspaceId(), resource.getResourceId());
    assertTrue(resource.partialEqual(getResource));
    assertNotNull(getResource.getCreatedDate());
    assertEquals(getResource.getCreatedDate(), getResource.getLastUpdatedDate());
    assertEquals(getResource.getCreatedByEmail(), getResource.getLastUpdatedByEmail());
  }

  @Test
  public void createGetControlledGcsBucket() {
    ControlledGcsBucketResource resource =
        ControlledResourceFixtures.makeDefaultControlledGcsBucketBuilder(workspaceUuid).build();
    createControlledResourceAndLog(resource);

    var getResource = resourceDao.getResource(resource.getWorkspaceId(), resource.getResourceId());
    assertTrue(resource.partialEqual(getResource));
    assertEquals(DEFAULT_USER_EMAIL, getResource.getLastUpdatedByEmail());
    assertNotNull(getResource.getLastUpdatedDate());
  }

  @Test
  public void createGetControlledFlexResource() {
    ControlledFlexibleResource resource =
        ControlledResourceFixtures.makeDefaultFlexResourceBuilder(workspaceUuid).build();
    createControlledResourceAndLog(resource);
    var getResource = resourceDao.getResource(resource.getWorkspaceId(), resource.getResourceId());
    assertTrue(resource.partialEqual(getResource));
    assertNotNull(getResource.getCreatedDate());
    assertNotNull(getResource.getLastUpdatedDate());
  }

  @Test
  public void
      createGetDeleteControlledBigQueryDataset_beforeLogIsWrite_lastUpdatedDateEqualsCreatedDate() {
    ControlledBigQueryDatasetResource resource =
        ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid).build();
    ControlledResourceFixtures.insertControlledResourceRow(resourceDao, resource);

    var getResource = resourceDao.getResource(resource.getWorkspaceId(), resource.getResourceId());
    assertTrue(resource.partialEqual(getResource));
    assertNotNull(getResource.getCreatedDate());
    assertEquals(getResource.getCreatedDate(), getResource.getLastUpdatedDate());
    assertEquals(getResource.getCreatedByEmail(), getResource.getLastUpdatedByEmail());
  }

  @Test
  public void createGetDeleteControlledBigQueryDataset() {
    ControlledBigQueryDatasetResource resource =
        ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid).build();
    createControlledResourceAndLog(resource);

    var getResource = resourceDao.getResource(resource.getWorkspaceId(), resource.getResourceId());
    assertTrue(resource.partialEqual(getResource));
    assertEquals(DEFAULT_USER_EMAIL, getResource.getLastUpdatedByEmail());
    assertNotNull(getResource.getLastUpdatedDate());
  }

  @Test
  public void
      createGetControlledAiNotebookInstance_beforeLogIsWrite_lastUpdatedDateEqualsCreatedDate() {
    ControlledResourceFields commonFields =
        ControlledResourceFixtures.makeNotebookCommonFieldsBuilder()
            .workspaceUuid(workspaceUuid)
            .build();
    ControlledAiNotebookInstanceResource resource =
        ControlledResourceFixtures.makeDefaultAiNotebookInstance().common(commonFields).build();
    ControlledResourceFixtures.insertControlledResourceRow(resourceDao, resource);

    var getResource = resourceDao.getResource(resource.getWorkspaceId(), resource.getResourceId());
    assertTrue(resource.partialEqual(getResource));
    assertNotNull(getResource.getCreatedDate());
    assertEquals(getResource.getCreatedDate(), getResource.getLastUpdatedDate());
    assertEquals(getResource.getCreatedByEmail(), getResource.getLastUpdatedByEmail());
  }

  @Test
  public void createGetControlledAiNotebookInstance() {
    ControlledResourceFields commonFields =
        ControlledResourceFixtures.makeNotebookCommonFieldsBuilder()
            .workspaceUuid(workspaceUuid)
            .build();
    ControlledAiNotebookInstanceResource resource =
        ControlledResourceFixtures.makeDefaultAiNotebookInstance().common(commonFields).build();
    ControlledResourceFixtures.insertControlledResourceRow(resourceDao, resource);
    activityLogDao.writeActivity(
        workspaceUuid,
        new DbWorkspaceActivityLog(
            DEFAULT_USER_EMAIL,
            DEFAULT_USER_SUBJECT_ID,
            OperationType.CREATE,
            resource.getResourceId().toString(),
            ActivityLogChangedTarget.RESOURCE));

    var getResource = resourceDao.getResource(resource.getWorkspaceId(), resource.getResourceId());
    assertTrue(resource.partialEqual(getResource));
    assertEquals(DEFAULT_USER_EMAIL, getResource.getLastUpdatedByEmail());
    assertNotNull(getResource.getLastUpdatedDate());
  }

  @Test
  public void updateControlledResourceRegion() {
    ControlledResourceFields commonFields =
        ControlledResourceFixtures.makeNotebookCommonFieldsBuilder()
            .workspaceUuid(workspaceUuid)
            .build();
    ControlledAiNotebookInstanceResource resource =
        ControlledResourceFixtures.makeDefaultAiNotebookInstance().common(commonFields).build();
    ControlledResourceFixtures.insertControlledResourceRow(resourceDao, resource);

    var newRegion = "great-new-world";

    assertTrue(resourceDao.updateControlledResourceRegion(resource.getResourceId(), newRegion));
    var newUserEmail = "foo";
    activityLogDao.writeActivity(
        workspaceUuid,
        new DbWorkspaceActivityLog(
            newUserEmail,
            UUID.randomUUID().toString(),
            OperationType.UPDATE,
            resource.getResourceId().toString(),
            ActivityLogChangedTarget.RESOURCE));

    ControlledResource controlledResource =
        resourceDao.getResource(workspaceUuid, resource.getResourceId()).castToControlledResource();
    assertEquals(newRegion, controlledResource.getRegion());
    assertEquals(newUserEmail, controlledResource.getLastUpdatedByEmail());
    assertFalse(
        controlledResource.getLastUpdatedDate().isBefore(controlledResource.getCreatedDate()));
  }

  @Test
  public void updateControlledResourceRegion_regionNull() {
    ControlledResourceFields commonFields =
        ControlledResourceFixtures.makeNotebookCommonFieldsBuilder()
            .workspaceUuid(workspaceUuid)
            .build();
    ControlledAiNotebookInstanceResource resource =
        ControlledResourceFixtures.makeDefaultAiNotebookInstance().common(commonFields).build();
    ControlledResourceFixtures.insertControlledResourceRow(resourceDao, resource);

    assertTrue(resourceDao.updateControlledResourceRegion(resource.getResourceId(), null));

    ControlledResource controlledResource =
        resourceDao.getResource(workspaceUuid, resource.getResourceId()).castToControlledResource();
    assertNull(controlledResource.getRegion());
  }

  @Test
  public void listAndDeleteControlledResourceInContext() {
    UUID workspaceUuid = createWorkspaceWithGcpContext(workspaceDao);
    ControlledGcsBucketResource bucket =
        ControlledResourceFixtures.makeDefaultControlledGcsBucketBuilder(workspaceUuid).build();
    ControlledBigQueryDatasetResource dataset =
        ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid).build();
    createControlledResourceAndLog(bucket);
    createControlledResourceAndLog(dataset);

    List<ControlledResource> gcpList =
        resourceDao.listControlledResources(workspaceUuid, CloudPlatform.GCP);
    List<ControlledResource> azureList =
        resourceDao.listControlledResources(workspaceUuid, CloudPlatform.AZURE);
    List<ControlledResource> allCloudList =
        resourceDao.listControlledResources(workspaceUuid, null);

    assertTrue(azureList.isEmpty());
    assertPartialEqualList(gcpList, List.of(bucket, dataset));
    assertPartialEqualList(allCloudList, List.of(bucket, dataset));

    assertTrue(resourceDao.deleteAllControlledResources(workspaceUuid, CloudPlatform.GCP));
    assertFalse(resourceDao.deleteAllControlledResources(workspaceUuid, CloudPlatform.AZURE));
    List<ControlledResource> listAfterDeletion =
        resourceDao.listControlledResources(workspaceUuid, CloudPlatform.GCP);
    assertTrue(listAfterDeletion.isEmpty());
    workspaceDao.deleteCloudContext(workspaceUuid, CloudPlatform.GCP);
    workspaceDao.deleteWorkspace(workspaceUuid);
  }

  private void assertPartialEqualList(
      List<ControlledResource> actual, List<ControlledResource> expected) {
    for (var resource : expected) {
      assertTrue(
          actual.stream()
              .anyMatch(
                  r ->
                      r.getResourceId().equals(resource.getResourceId())
                          && r.partialEqual(resource)));
    }
  }

  @Test
  public void duplicateControlledBucketNameRejected() {
    final String clashingBucketName = "not-a-pail";
    final ControlledGcsBucketResource initialResource =
        ControlledResourceFixtures.makeDefaultControlledGcsBucketBuilder(workspaceUuid)
            .bucketName(clashingBucketName)
            .build();
    ControlledResourceFixtures.insertControlledResourceRow(resourceDao, initialResource);

    final UUID workspaceId2 = createWorkspaceWithGcpContext(workspaceDao);
    final ControlledGcsBucketResource duplicatingResource =
        ControlledResourceFixtures.makeDefaultControlledGcsBucketBuilder(workspaceId2)
            .bucketName(clashingBucketName)
            .build();

    assertThrows(
        DuplicateResourceException.class,
        () ->
            ControlledResourceFixtures.insertControlledResourceRow(
                resourceDao, duplicatingResource));
  }

  // AI Notebooks are unique on the tuple {instanceId, location, projectId } in addition
  // to the underlying requirement that resource ID and resource names are unique within a
  // workspace.
  @Test
  public void
      createAiNotebook_duplicateCloudInstanceId_rejectedWhenInSameCloudProjectAndLocation() {
    var cloudInstanceId = TestUtils.appendRandomNumber("my-cloud-instance-id");
    ControlledResourceFields commonFields1 =
        ControlledResourceFixtures.makeNotebookCommonFieldsBuilder()
            .workspaceUuid(workspaceUuid)
            .build();
    ControlledAiNotebookInstanceResource initialResource =
        ControlledResourceFixtures.makeDefaultAiNotebookInstance()
            .common(commonFields1)
            .instanceId(cloudInstanceId)
            .build();

    ControlledResourceFixtures.insertControlledResourceRow(resourceDao, initialResource);
    assertTrue(
        initialResource.partialEqual(
            resourceDao.getResource(
                initialResource.getWorkspaceId(), initialResource.getResourceId())));

    ControlledResourceFields commonFields2 =
        ControlledResourceFixtures.makeNotebookCommonFieldsBuilder()
            .workspaceUuid(workspaceUuid)
            .name("resource-2")
            .build();
    final ControlledResource duplicatingResource =
        ControlledResourceFixtures.makeDefaultAiNotebookInstance()
            .common(commonFields2)
            .instanceId(cloudInstanceId)
            .build();
    assertThrows(
        DuplicateResourceException.class,
        () ->
            ControlledResourceFixtures.insertControlledResourceRow(
                resourceDao, duplicatingResource));

    ControlledResourceFields commonFields3 =
        ControlledResourceFixtures.makeNotebookCommonFieldsBuilder()
            .workspaceUuid(createWorkspaceWithGcpContext(workspaceDao))
            .name("resource-3")
            .build();
    ControlledResource resourceWithDifferentWorkspaceId =
        ControlledResourceFixtures.makeDefaultAiNotebookInstance()
            .common(commonFields3)
            .instanceId(cloudInstanceId)
            .build();

    // should be fine: separate workspaces implies separate gcp projects
    createControlledResourceAndLog(resourceWithDifferentWorkspaceId);
    assertTrue(
        resourceWithDifferentWorkspaceId.partialEqual(
            resourceDao.getResource(
                resourceWithDifferentWorkspaceId.getWorkspaceId(),
                resourceWithDifferentWorkspaceId.getResourceId())));

    ControlledResourceFields commonFields5 =
        ControlledResourceFixtures.makeNotebookCommonFieldsBuilder()
            .workspaceUuid(workspaceUuid)
            .name("resource-5")
            .build();
    final ControlledAiNotebookInstanceResource resourceWithDefaultLocation =
        ControlledResourceFixtures.makeDefaultAiNotebookInstance()
            .common(commonFields5)
            .instanceId(cloudInstanceId)
            .location(null)
            .build();

    assertThrows(
        DuplicateResourceException.class,
        () ->
            resourceDao.createResourceStart(
                resourceWithDefaultLocation, UUID.randomUUID().toString()));
  }

  @Test
  public void duplicateBigQueryDatasetRejected() {
    String datasetName1 = "dataset1";
    String projectId1 = "projectId1";
    String projectId2 = "projectId2";
    final ControlledBigQueryDatasetResource initialResource =
        ControlledBigQueryDatasetResource.builder()
            .common(ControlledResourceFixtures.makeDefaultControlledResourceFields(workspaceUuid))
            .projectId(projectId1)
            .datasetName(datasetName1)
            .build();
    createControlledResourceAndLog(initialResource);

    UUID workspaceId2 = createWorkspaceWithGcpContext(workspaceDao);
    try {
      // This is in a different workspace (and so a different cloud context), so it is not a
      // conflict
      // even with the same Dataset ID.
      final ControlledBigQueryDatasetResource uniqueResource =
          ControlledBigQueryDatasetResource.builder()
              .common(ControlledResourceFixtures.makeDefaultControlledResourceFields(workspaceId2))
              .datasetName(datasetName1)
              .projectId(projectId2)
              .build();
      createControlledResourceAndLog(uniqueResource);

      // This is in the same workspace as initialResource, so it should be a conflict.
      final ControlledBigQueryDatasetResource duplicatingResource =
          ControlledBigQueryDatasetResource.builder()
              .common(ControlledResourceFixtures.makeDefaultControlledResourceFields(workspaceUuid))
              .projectId(projectId1)
              .datasetName(datasetName1)
              .build();

      assertThrows(
          DuplicateResourceException.class,
          () -> createControlledResourceAndLog(duplicatingResource));
    } finally {
      resourceDao.deleteAllControlledResources(workspaceId2, CloudPlatform.GCP);
    }
  }

  @Test
  public void updateResourceProperties_propertiesUpdated() {
    ControlledBigQueryDatasetResource resource =
        ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid).build();
    createControlledResourceAndLog(resource);
    Map<String, String> properties = Map.of("foo", "bar1", "sweet", "cake");

    Map<String, String> expectedUpdatedProperties = new HashMap<>();
    expectedUpdatedProperties.putAll(DEFAULT_RESOURCE_PROPERTIES);
    expectedUpdatedProperties.putAll(properties);
    resourceDao.updateResourceProperties(workspaceUuid, resource.getResourceId(), properties);

    assertEquals(
        expectedUpdatedProperties,
        resourceDao
            .getResource(resource.getWorkspaceId(), resource.getResourceId())
            .getProperties());
  }

  @Test
  public void updateResourceProperties_lastUpdatedBy() {
    ControlledBigQueryDatasetResource resource =
        ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid).build();
    createControlledResourceAndLog(resource);
    Map<String, String> properties = Map.of("foo", "bar1", "sweet", "cake");
    var resourceBeforeUpdate =
        resourceDao.getResource(resource.getWorkspaceId(), resource.getResourceId());

    Map<String, String> expectedUpdatedProperties = new HashMap<>();
    expectedUpdatedProperties.putAll(DEFAULT_RESOURCE_PROPERTIES);
    expectedUpdatedProperties.putAll(properties);
    resourceDao.updateResourceProperties(workspaceUuid, resource.getResourceId(), properties);
    var userEmail = "foo";
    activityLogDao.writeActivity(
        workspaceUuid,
        new DbWorkspaceActivityLog(
            userEmail,
            UUID.randomUUID().toString(),
            OperationType.UPDATE,
            resource.getResourceId().toString(),
            ActivityLogChangedTarget.RESOURCE));

    var resourceAfterUpdate =
        resourceDao.getResource(resource.getWorkspaceId(), resource.getResourceId());
    assertEquals(userEmail, resourceAfterUpdate.getLastUpdatedByEmail());
    assertTrue(
        resourceAfterUpdate
            .getLastUpdatedDate()
            .isAfter(resourceBeforeUpdate.getLastUpdatedDate()));
  }

  @Test
  public void updateResourceProperties_resourceNotFound_throwsWorkspaceNotFoundException() {
    Map<String, String> properties = Map.of("foo", "bar1", "sweet", "cake");

    assertThrows(
        ResourceNotFoundException.class,
        () -> resourceDao.updateResourceProperties(workspaceUuid, UUID.randomUUID(), properties));
  }

  @Test
  public void
      updateResourceProperties_emptyUpdateProperties_throwsMissingRequiredFieldsException() {
    ControlledBigQueryDatasetResource resource =
        ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid).build();
    createControlledResourceAndLog(resource);

    assertThrows(
        MissingRequiredFieldsException.class,
        () ->
            resourceDao.updateResourceProperties(
                workspaceUuid, resource.getResourceId(), Map.of()));
  }

  @Test
  public void deleteResourceProperties_resourcePropertiesDeleted() {
    ControlledBigQueryDatasetResource resource =
        ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid).build();
    createControlledResourceAndLog(resource);

    resourceDao.deleteResourceProperties(
        workspaceUuid,
        resource.getResourceId(),
        DEFAULT_RESOURCE_PROPERTIES.keySet().stream().toList());
    assertTrue(
        resourceDao.getResource(workspaceUuid, resource.getResourceId()).getProperties().isEmpty());
  }

  @Test
  public void deleteResourceProperties_nonExistingKeys_nothingIsDeleted() {
    UUID workspaceUuid = createWorkspaceWithGcpContext(workspaceDao);
    try {
      ControlledBigQueryDatasetResource resource =
          ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid).build();
      createControlledResourceAndLog(resource);

      resourceDao.deleteResourceProperties(
          workspaceUuid, resource.getResourceId(), List.of(RandomStringUtils.randomAlphabetic(3)));

      assertEquals(
          resource.getProperties(),
          resourceDao.getResource(workspaceUuid, resource.getResourceId()).getProperties());
    } finally {
      resourceDao.deleteAllControlledResources(workspaceUuid, CloudPlatform.GCP);
    }
  }

  @Test
  public void deleteResourceProperties_noKeySpecified_throwsMissingRequiredFieldsException() {
    UUID workspaceUuid = createWorkspaceWithGcpContext(workspaceDao);
    try {
      ControlledBigQueryDatasetResource resource =
          ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid).build();
      createControlledResourceAndLog(resource);

      assertThrows(
          MissingRequiredFieldsException.class,
          () ->
              resourceDao.deleteResourceProperties(
                  workspaceUuid, resource.getResourceId(), List.of()));
    } finally {
      resourceDao.deleteAllControlledResources(workspaceUuid, CloudPlatform.GCP);
    }
  }

  @Test
  void gcsBucketWithUnderscore_retrieve() {
    UUID workspaceUuid = createWorkspaceWithGcpContext(workspaceDao);
    var resourceId = UUID.randomUUID();
    var bucketName = "gcs_bucket_with_underscore_name";
    // This is an artificially contrived situation where we create a gcs bucket with an underscore.
    var originalResource =
        new ControlledGcsBucketResource(
            new DbResource()
                .workspaceUuid(workspaceUuid)
                .resourceId(resourceId)
                .name(TestUtils.appendRandomNumber("resourcename"))
                .resourceType(WsmResourceType.CONTROLLED_GCP_GCS_BUCKET)
                .stewardshipType(StewardshipType.CONTROLLED)
                .description("This is a bucket with underscore name")
                .cloningInstructions(CloningInstructions.COPY_NOTHING)
                .assignedUser(null)
                .privateResourceState(PrivateResourceState.NOT_APPLICABLE)
                .accessScope(AccessScopeType.ACCESS_SCOPE_SHARED)
                .managedBy(ManagedByType.MANAGED_BY_USER)
                .applicationId(null)
                .resourceLineage(List.of())
                .properties(Map.of())
                .createdByEmail("foo@bar.com")
                .region("us-central1"),
            bucketName);

    ControlledResourceFixtures.insertControlledResourceRow(resourceDao, originalResource);

    ControlledGcsBucketResource bucket =
        resourceDao
            .getResource(workspaceUuid, resourceId)
            .castByEnum(WsmResourceType.CONTROLLED_GCP_GCS_BUCKET);

    assertEquals(bucketName, bucket.getBucketName());
  }

  @Test
  public void listControlledResourceWithoutRegion() {
    UUID workspaceUuid = createWorkspaceWithGcpContext(workspaceDao);
    UUID workspaceUuid2 = createWorkspaceWithGcpContext(workspaceDao);
    UUID workspaceUuid3 = createWorkspaceWithGcpContext(workspaceDao);
    for (int i = 0; i < 5; i++) {
      ControlledBigQueryDatasetResource dataset =
          ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid)
              .common(
                  makeDefaultControlledResourceFieldsBuilder()
                      .workspaceUuid(workspaceUuid)
                      .region(null)
                      .build())
              .build();
      ControlledGcsBucketResource bucket =
          ControlledResourceFixtures.makeDefaultControlledGcsBucketBuilder(workspaceUuid2)
              .common(
                  makeDefaultControlledResourceFieldsBuilder()
                      .workspaceUuid(workspaceUuid2)
                      .region(null)
                      .build())
              .build();
      ControlledAiNotebookInstanceResource notebook =
          ControlledResourceFixtures.makeDefaultAiNotebookInstance()
              .common(
                  makeNotebookCommonFieldsBuilder()
                      .workspaceUuid(workspaceUuid3)
                      .region(null)
                      .build())
              .build();
      ControlledResourceFixtures.insertControlledResourceRow(resourceDao, dataset);
      ControlledResourceFixtures.insertControlledResourceRow(resourceDao, bucket);
      ControlledResourceFixtures.insertControlledResourceRow(resourceDao, notebook);
    }

    assertEquals(
        15, resourceDao.listControlledResourcesWithMissingRegion(CloudPlatform.GCP).size());
    assertTrue(resourceDao.listControlledResourcesWithMissingRegion(CloudPlatform.AZURE).isEmpty());
    resourceDao.deleteAllControlledResources(workspaceUuid, CloudPlatform.GCP);
    resourceDao.deleteAllControlledResources(workspaceUuid2, CloudPlatform.GCP);
    resourceDao.deleteAllControlledResources(workspaceUuid3, CloudPlatform.GCP);
  }

  @Test
  public void listControlledBigQueryDatasetsWithoutLifetime() {
    resourceDao.deleteAllControlledResources(workspaceUuid, CloudPlatform.GCP);

    UUID workspaceWithGcpContext = createWorkspaceWithGcpContext(workspaceDao);

    var emptyList = resourceDao.listControlledBigQueryDatasetsWithoutBothLifetime();
    assertEquals(0, emptyList.size());
    try {
      for (int i = 0; i < 5; i++) {
        ControlledBigQueryDatasetResource dataset =
            ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid)
                .defaultTableLifetime(null)
                .defaultPartitionLifetime(null)
                .build();
        ControlledResourceFixtures.insertControlledResourceRow(resourceDao, dataset);
      }

      ControlledBigQueryDatasetResource datasetWithLifetime =
          ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid)
              .defaultTableLifetime(DEFAULT_CREATED_BIG_QUERY_TABLE_LIFETIME)
              .defaultPartitionLifetime(DEFAULT_CREATED_BIG_QUERY_PARTITION_LIFETIME)
              .build();
      ControlledResourceFixtures.insertControlledResourceRow(resourceDao, datasetWithLifetime);

      var ans = resourceDao.listControlledBigQueryDatasetsWithoutBothLifetime().size();
      assertEquals(5, ans);
    } finally {
      resourceDao.deleteAllControlledResources(workspaceWithGcpContext, CloudPlatform.GCP);
    }
  }

  @Test
  public void updateBigQueryDatasetDefaultTableAndPartitionLifetime() {
    ControlledBigQueryDatasetResource resource =
        ControlledResourceFixtures.makeDefaultControlledBqDatasetBuilder(workspaceUuid).build();
    ControlledResourceFixtures.insertControlledResourceRow(resourceDao, resource);

    ControlledBigQueryDatasetResource resourceBeforeUpdate =
        resourceDao
            .getResource(resource.getWorkspaceId(), resource.getResourceId())
            .castToControlledResource()
            .castByEnum(WsmResourceType.CONTROLLED_GCP_BIG_QUERY_DATASET);

    assertEquals(
        DEFAULT_CREATED_BIG_QUERY_TABLE_LIFETIME, resourceBeforeUpdate.getDefaultTableLifetime());
    assertEquals(
        DEFAULT_CREATED_BIG_QUERY_PARTITION_LIFETIME,
        resourceBeforeUpdate.getDefaultPartitionLifetime());

    resourceDao.updateBigQueryDatasetDefaultTableAndPartitionLifetime(
        resourceBeforeUpdate, 6000L, 6001L);

    ControlledBigQueryDatasetResource resourceAfterUpdate =
        resourceDao
            .getResource(resource.getWorkspaceId(), resource.getResourceId())
            .castToControlledResource()
            .castByEnum(WsmResourceType.CONTROLLED_GCP_BIG_QUERY_DATASET);

    assertEquals(6000L, resourceAfterUpdate.getDefaultTableLifetime());
    assertEquals(6001L, resourceAfterUpdate.getDefaultPartitionLifetime());
  }

  private void createControlledResourceAndLog(ControlledResource resource) {
    resourceDao.createResourceStart(resource, UUID.randomUUID().toString());
    activityLogDao.writeActivity(
        workspaceUuid,
        new DbWorkspaceActivityLog(
            DEFAULT_USER_EMAIL,
            DEFAULT_USER_SUBJECT_ID,
            OperationType.CREATE,
            resource.getResourceId().toString(),
            ActivityLogChangedTarget.RESOURCE));
  }
}
