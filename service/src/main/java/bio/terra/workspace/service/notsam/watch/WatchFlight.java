package bio.terra.workspace.service.notsam.watch;

import bio.terra.stairway.Flight;
import bio.terra.stairway.FlightContext;
import bio.terra.stairway.FlightMap;
import bio.terra.stairway.Step;
import bio.terra.stairway.StepResult;
import bio.terra.stairway.exception.RetryException;
import bio.terra.workspace.common.utils.FlightBeanBag;
import bio.terra.workspace.service.notsam.AclManager;
import bio.terra.workspace.service.spice.SpiceService;
import com.authzed.api.v1.Core;
import com.authzed.api.v1.WatchServiceOuterClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Iterator;
import java.util.UUID;

public class WatchFlight extends Flight {

  public WatchFlight(FlightMap inputParameters, Object applicationContext) {
    super(inputParameters, applicationContext);
    FlightBeanBag beanBag = (FlightBeanBag) applicationContext;
    addStep(new WatchStep(beanBag.getSpiceService(), beanBag.getAclManager()));
  }

  // TODO: maintain persistent state, support multiple pods, etc, etc.
  //  For now, this is ephemeral
  public static class WatchStep implements Step {
    private static final Logger logger = LoggerFactory.getLogger(WatchStep.class);
    private final SpiceService spiceService;
    private final AclManager aclManager;

    public WatchStep(SpiceService spiceService, AclManager aclManager) {
      this.spiceService = spiceService;
      this.aclManager = aclManager;
    }

    @Override
    public StepResult doStep(FlightContext context) throws InterruptedException, RetryException {
      Iterator<WatchServiceOuterClass.WatchResponse> watchIterator = spiceService.watch("workspace", null);

      while (watchIterator.hasNext()) {
        WatchServiceOuterClass.WatchResponse response = watchIterator.next();

        for (Core.RelationshipUpdate update : response.getUpdatesList()) {
          Core.Relationship relationship = update.getRelationship();
          logger.info(
            "WATCH {} resource {}:{}  relation {}  subject {}:{}",
            update.getOperation(),
            relationship.getResource().getObjectType(),
            relationship.getResource().getObjectId(),
            relationship.getRelation(),
            relationship.getSubject().getObject().getObjectType(),
            relationship.getSubject().getObject().getObjectId());

          aclManager.workspaceEvent(UUID.fromString(relationship.getResource().getObjectId()), update.getOperation());
        }
      }
      return StepResult.getStepResultSuccess();
    }

    @Override
    public StepResult undoStep(FlightContext context) throws InterruptedException {
      return null;
    }
  }

}
