package bio.terra.workspace.app;

import bio.terra.common.db.DataSourceInitializer;
import bio.terra.common.migrate.LiquibaseMigrator;
import bio.terra.common.sam.SamRetry;
import bio.terra.landingzone.library.LandingZoneMain;
import bio.terra.workspace.app.configuration.external.FeatureConfiguration;
import bio.terra.workspace.app.configuration.external.WorkspaceDatabaseConfiguration;
import bio.terra.workspace.service.iam.SamService;
import bio.terra.workspace.service.job.JobService;
import bio.terra.workspace.service.notsam.NotSamService;
import bio.terra.workspace.service.notsam.UserManager;
import bio.terra.workspace.service.resource.controlled.ControlledResourceService;
import bio.terra.workspace.service.workspace.WsmApplicationService;
import javax.sql.DataSource;

import org.broadinstitute.dsde.workbench.client.sam.ApiException;
import org.broadinstitute.dsde.workbench.client.sam.api.UsersApi;
import org.broadinstitute.dsde.workbench.client.sam.model.UserStatusInfo;
import org.springframework.context.ApplicationContext;

public final class StartupInitializer {
  private static final String changelogPath = "db/changelog.xml";

  public static void initialize(ApplicationContext applicationContext) {
    // Initialize or upgrade the database depending on the configuration
    LiquibaseMigrator migrateService = applicationContext.getBean(LiquibaseMigrator.class);
    WorkspaceDatabaseConfiguration workspaceDatabaseConfiguration =
        applicationContext.getBean(WorkspaceDatabaseConfiguration.class);
    JobService jobService = applicationContext.getBean(JobService.class);
    WsmApplicationService appService = applicationContext.getBean(WsmApplicationService.class);
    FeatureConfiguration featureConfiguration =
        applicationContext.getBean(FeatureConfiguration.class);
    NotSamService notSamService = applicationContext.getBean(NotSamService.class);
    SamService samService = applicationContext.getBean(SamService.class);

    // Log the state of the feature flags
    featureConfiguration.logFeatures();

    // Migrate the database
    DataSource workspaceDataSource =
        DataSourceInitializer.initializeDataSource(workspaceDatabaseConfiguration);
    if (workspaceDatabaseConfiguration.isInitializeOnStart()) {
      migrateService.initialize(changelogPath, workspaceDataSource);
    } else if (workspaceDatabaseConfiguration.isUpgradeOnStart()) {
      migrateService.upgrade(changelogPath, workspaceDataSource);
    }

    // The JobService initialization also handles Stairway initialization.
    jobService.initialize();

    // Process the WSM application configuration
    appService.configure();

    // Initialize Terra Landing Zone library
    LandingZoneMain.initialize(applicationContext, migrateService);

    // TODO: This is all temporary and ephemeral
    // Get the username of the "wsm SA" == current application credential
    String wsmSaEmail;
    try {
      String wsmAccessToken = samService.getWsmServiceAccountToken();
      UsersApi usersApi = samService.samUsersApi(wsmAccessToken);
      UserStatusInfo userStatusInfo = SamRetry.retry(usersApi::getUserStatusInfo);
      wsmSaEmail = userStatusInfo.getUserEmail();
    } catch (ApiException | InterruptedException e) {
      throw new RuntimeException(e);
    }

    // Initialize spiceDB, users and proxy groups
    notSamService.initialize(wsmSaEmail);

    // NOTE:
    // Fill in this method with any other initialization that needs to happen
    // between the point of having the entire application initialized and
    // the point of opening the port to start accepting REST requests.
    // TODO (PF-2269): Clean this up once the back-fill is done in all Terra environments.
    ControlledResourceService controlledResourceService =
        applicationContext.getBean(ControlledResourceService.class);
    controlledResourceService.updateControlledBigQueryDatasetsLifetimeAsync();


  }
}
