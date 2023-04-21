package bio.terra.workspace.service.spice;

import com.authzed.api.v1.Core;
import com.authzed.api.v1.Core.ObjectReference;
import com.authzed.api.v1.Core.Relationship;
import com.authzed.api.v1.Core.RelationshipUpdate;
import com.authzed.api.v1.Core.RelationshipUpdate.Operation;
import com.authzed.api.v1.Core.SubjectReference;
import com.authzed.api.v1.Core.ZedToken;
import com.authzed.api.v1.PermissionService;
import com.authzed.api.v1.PermissionService.CheckPermissionRequest;
import com.authzed.api.v1.PermissionService.CheckPermissionResponse;
import com.authzed.api.v1.PermissionService.CheckPermissionResponse.Permissionship;
import com.authzed.api.v1.PermissionService.Consistency;
import com.authzed.api.v1.PermissionService.DeleteRelationshipsRequest;
import com.authzed.api.v1.PermissionService.DeleteRelationshipsResponse;
import com.authzed.api.v1.PermissionService.LookupResourcesRequest;
import com.authzed.api.v1.PermissionService.LookupResourcesResponse;
import com.authzed.api.v1.PermissionService.RelationshipFilter;
import com.authzed.api.v1.PermissionService.WriteRelationshipsRequest;
import com.authzed.api.v1.PermissionService.WriteRelationshipsResponse;
import com.authzed.api.v1.PermissionsServiceGrpc;
import com.authzed.api.v1.SchemaServiceGrpc;
import com.authzed.api.v1.SchemaServiceOuterClass.WriteSchemaRequest;
import com.authzed.api.v1.SchemaServiceOuterClass.WriteSchemaResponse;
import com.authzed.api.v1.WatchServiceGrpc;
import com.authzed.api.v1.WatchServiceOuterClass;
import com.authzed.grpcutil.BearerToken;
import com.google.common.io.Resources;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** This class provides the low level interface to SpiceDB. */
@Component
public class SpiceService {
  private static final Logger logger = LoggerFactory.getLogger(SpiceService.class);
  // TODO(spice): put this into configuration
  private static final String TARGET = "localhost:50051";
  private static final String TOKEN = "dd_test_token";

  private final PermissionsServiceGrpc.PermissionsServiceBlockingStub grpcPermissionsService;
  private final WatchServiceGrpc.WatchServiceBlockingStub grpcWatchServiceBlockingStub;
  private final SchemaServiceGrpc.SchemaServiceBlockingStub schemaServiceBlockingStub;

  private ZedToken zedToken;

  public SpiceService() {
    // Initialize services
    ManagedChannel channel = ManagedChannelBuilder.forTarget(TARGET).usePlaintext().build();
    BearerToken bearerToken = new BearerToken(TOKEN);
    schemaServiceBlockingStub =
        SchemaServiceGrpc.newBlockingStub(channel).withCallCredentials(bearerToken);
    grpcPermissionsService =
        PermissionsServiceGrpc.newBlockingStub(channel).withCallCredentials(bearerToken);

    grpcWatchServiceBlockingStub =
        WatchServiceGrpc.newBlockingStub(channel).withCallCredentials(bearerToken);
  }

  public void initialize() {
    // Write schema to spiceDb
    logger.info("Writing schema to spice");
    String schema = readSchemaFromResources();
    var writeRequest = WriteSchemaRequest.newBuilder().setSchema(schema).build();

    WriteSchemaResponse response;
    try {
      response = schemaServiceBlockingStub.writeSchema(writeRequest);
      logger.info("Write schema response: " + response.toString());
    } catch (Exception e) {
      logger.warn("RPC failed: {}", e.getMessage());
    }
  }

  /**
   * TODO: probably want to change to the non-blocking stub and let the upper layer provide the callback.
   *
   * @param resourceType like "workspace"
   * @param startZedToken like null
   * @return iterator to process a continuous flow of watch responses
   */
  public Iterator<WatchServiceOuterClass.WatchResponse> watch(String resourceType, @Nullable ZedToken startZedToken) {

    var builder =
        WatchServiceOuterClass.WatchRequest.newBuilder().addOptionalObjectTypes(resourceType);

    if (startZedToken != null) {
      builder.setOptionalStartCursor(startZedToken);
    }

    return  grpcWatchServiceBlockingStub.watch(builder.build());

  }

  public void createRelationship(
      String subjectType,
      String subjectId,
      String resourceType,
      String resourceId,
      String role,
      @Nullable String relation) {
    writeRelationship(
        Operation.OPERATION_CREATE,
        subjectType,
        subjectId,
        resourceType,
        resourceId,
        role,
        relation);
  }

  public void deleteRelationship(
      String subjectType,
      String subjectId,
      String resourceType,
      String resourceId,
      String role,
      @Nullable String relation) {
    writeRelationship(
        Operation.OPERATION_DELETE,
        subjectType,
        subjectId,
        resourceType,
        resourceId,
        role,
        relation);
  }

  private void writeRelationship(
      Operation operation,
      String subjectType,
      String subjectId,
      String resourceType,
      String resourceId,
      String role,
      @Nullable String relation) {
    logger.info(
        "{} relationship {}:{} as {} to {}:{}{}",
        (operation == Operation.OPERATION_CREATE ? "create" : "delete"),
        subjectType,
        subjectId,
        role,
        resourceType,
        resourceId,
        (relation == null ? "" : "#" + relation));

    var subjectBuilder =
        SubjectReference.newBuilder()
            .setObject(
                ObjectReference.newBuilder()
                    .setObjectType(subjectType)
                    .setObjectId(subjectId)
                    .build());
    if (relation != null) {
      subjectBuilder.setOptionalRelation(relation);
    }

    var request =
        WriteRelationshipsRequest.newBuilder()
            .addUpdates(
                RelationshipUpdate.newBuilder()
                    .setOperation(operation)
                    .setRelationship(
                        Relationship.newBuilder()
                            .setResource(
                                ObjectReference.newBuilder()
                                    .setObjectType(resourceType)
                                    .setObjectId(resourceId)
                                    .build())
                            .setRelation(role)
                            .setSubject(subjectBuilder.build())
                            .build())
                    .build())
            .build();

    try {
      WriteRelationshipsResponse response = grpcPermissionsService.writeRelationships(request);
      // Save the zed token after every update we do, for consistency
      zedToken = response.getWrittenAt();
      logger.info(
          "{} relationship {}:{} as {} to {}:{}{}- zedToken: {}",
          (operation == Operation.OPERATION_CREATE ? "Created" : "Deleted"),
          subjectType,
          subjectId,
          role,
          resourceType,
          resourceId,
          (relation == null ? "" : "#" + relation),
          zedToken);
    } catch (Exception e) {
      logger.warn("RPC failed: {}", e.getMessage());
    }
  }

  public void deleteResourceRelationships(
      String resourceType,
      String resourceId,
      @Nullable String resourceRelation,
      @Nullable String subjectType,
      @Nullable String subjectId,
      @Nullable String subjectRelation) {

    var filter =
        buildRelationshipFilter(
            resourceType, resourceId, resourceRelation, subjectType, subjectId, subjectRelation);

    var builder = DeleteRelationshipsRequest.newBuilder().setRelationshipFilter(filter);

    try {
      DeleteRelationshipsResponse response =
          grpcPermissionsService.deleteRelationships(builder.build());
      zedToken = response.getDeletedAt();
    } catch (Exception e) {
      logger.warn("RPC failed: {}", e.getMessage());
      throw new RuntimeException("Delete relationships failed", e);
    }
  }

  public record SpiceRelationship(
      String resourceType,
      String resourceId,
      String resourceRelation,
      String subjectType,
      String subjectId,
      @Nullable String subjectRelation) {}

  public List<SpiceRelationship> readResourceRelationships(
      String resourceType,
      @Nullable String resourceId,
      @Nullable String resourceRelation,
      @Nullable String subjectType,
      @Nullable String subjectId,
      @Nullable String subjectRelation) {

    var filter =
        buildRelationshipFilter(
            resourceType, resourceId, resourceRelation, subjectType, subjectId, subjectRelation);

    var builder =
        PermissionService.ReadRelationshipsRequest.newBuilder().setRelationshipFilter(filter);

    List<SpiceRelationship> resultList = new ArrayList<>();
    try {
      Iterator<PermissionService.ReadRelationshipsResponse> responseList =
          grpcPermissionsService.readRelationships(builder.build());
      while (responseList.hasNext()) {
        PermissionService.ReadRelationshipsResponse response = responseList.next();
        if (zedToken == null) {
          zedToken = response.getReadAt();
        }

        Relationship relationship = response.getRelationship();
        ObjectReference resource = relationship.getResource();
        SubjectReference subject = relationship.getSubject();

        resultList.add(
            new SpiceRelationship(
                resource.getObjectType(),
                resource.getObjectId(),
                relationship.getRelation(),
                subject.getObject().getObjectType(),
                subject.getObject().getObjectId(),
                subject.getOptionalRelation()));
      }
    } catch (Exception e) {
      logger.warn("RPC failed: {}", e.getMessage());
      throw new RuntimeException("Read relationships failed", e);
    }

    return resultList;
  }

  private RelationshipFilter buildRelationshipFilter(
      String resourceType,
      @Nullable String resourceId,
      @Nullable String resourceRelation,
      @Nullable String subjectType,
      @Nullable String subjectId,
      @Nullable String subjectRelation) {

    var filterBuilder = RelationshipFilter.newBuilder().setResourceType(resourceType);

    // This is laborious, but the spice API will not accept NULL as meaning unspecified.
    if (resourceId != null) {
      filterBuilder.setOptionalResourceId(resourceId);
    }
    if (resourceRelation != null) {
      filterBuilder.setOptionalRelation(resourceRelation);
    }
    if (subjectType != null) {
      var subjectBuilder = PermissionService.SubjectFilter.newBuilder().setSubjectType(subjectType);
      if (subjectId != null) {
        subjectBuilder.setOptionalSubjectId(subjectId);
      }
      if (subjectRelation != null) {
        subjectBuilder.setOptionalRelation(
            PermissionService.SubjectFilter.RelationFilter.newBuilder()
                .setRelation(subjectRelation)
                .build());
      }
      filterBuilder.setOptionalSubjectFilter(subjectBuilder.build());
    }

    return filterBuilder.build();
  }

  // Permission check is always against a user
  public boolean checkPermission(
      String userId, String resourceType, String resourceId, String permission) {
    logger.info(
        "Check user:{} permission {} on {}:{}", userId, permission, resourceType, resourceId);

    var builder =
        CheckPermissionRequest.newBuilder()
            .setResource(
                ObjectReference.newBuilder()
                    .setObjectType(resourceType)
                    .setObjectId(resourceId)
                    .build())
            .setSubject(
                SubjectReference.newBuilder()
                    .setObject(
                        ObjectReference.newBuilder()
                            .setObjectType("user")
                            .setObjectId(userId)
                            .build())
                    .build())
            .setPermission(permission);

    // If zedToken isn't set yet, do a fully consistent request and store the
    // zedToken returned in the response (below)
    if (zedToken != null) {
      builder.setConsistency(Consistency.newBuilder().setAtLeastAsFresh(zedToken).build());
    } else {
      builder.setConsistency(Consistency.newBuilder().setFullyConsistent(true).build());
    }

    CheckPermissionResponse response;
    try {
      response = grpcPermissionsService.checkPermission(builder.build());
      if (zedToken == null) {
        zedToken = response.getCheckedAt();
      }
    } catch (Exception e) {
      logger.warn("RPC failed: {}", e.getMessage());
      throw new RuntimeException("Permission check failed", e);
    }

    Permissionship permissionship = response.getPermissionship();
    logger.info(
        "Checked user:{} permission {} on {}:{} -> {}",
        userId,
        permission,
        resourceType,
        resourceId,
        permissionship);

    return switch (permissionship) {
      case PERMISSIONSHIP_CONDITIONAL_PERMISSION, PERMISSIONSHIP_HAS_PERMISSION -> true;
      case PERMISSIONSHIP_NO_PERMISSION -> false;
      case UNRECOGNIZED, PERMISSIONSHIP_UNSPECIFIED -> throw new IllegalArgumentException(
          "Unrecognized permission");
    };
  }

  // Record for multi-value return below
  public record GroupSubject(String resourceType, String resourceId, String permission) {}

  /**
   * Expand a group, returning the subjects and their permissions. This is not generic, since it has
   * to know the structure of the expand and parse out the parts that make the groups. Note that the
   * "permissions" returned are based on relationships and are not permissions in the Spice schema.
   *
   * @param groupId identifier of the group we are expanding
   * @return list of group subjects
   */
  public List<GroupSubject> expandGroup(String groupId) {
    var builder =
        PermissionService.ExpandPermissionTreeRequest.newBuilder()
            .setPermission("membership")
            .setResource(
                ObjectReference.newBuilder().setObjectType("group").setObjectId(groupId).build());

    // If zedToken isn't set yet, do a fully consistent request and store the
    // zedToken returned in the response (below)
    if (zedToken != null) {
      builder.setConsistency(Consistency.newBuilder().setAtLeastAsFresh(zedToken).build());
    } else {
      builder.setConsistency(Consistency.newBuilder().setFullyConsistent(true).build());
    }

    Core.PermissionRelationshipTree root;
    try {
      var response = grpcPermissionsService.expandPermissionTree(builder.build());
      if (zedToken == null) {
        zedToken = response.getExpandedAt();
      }
      root = response.getTreeRoot();
    } catch (Exception e) {
      logger.warn("RPC failed: {}", e.getMessage());
      throw new RuntimeException("Resource lookup failed", e);
    }

    // TODO: this won't be right with the proxy_group change
    // We expect the structure to be:
    // UNION
    //  group:[queried group]->member
    //    user:[user-id]  (direct user)
    //    group:[group-id]->membership (direct group)
    //  group:[queried group]->admin
    //    user:[user-id]  (direct user)
    //    group:[group-id]->membership (direct group)
    List<GroupSubject> memberList = new ArrayList<>();
    if (!root.hasIntermediate()) {
      throw new RuntimeException("No intermediate");
    }
    Core.AlgebraicSubjectSet union = root.getIntermediate();
    if (union.getOperation() != Core.AlgebraicSubjectSet.Operation.OPERATION_UNION) {
      throw new RuntimeException("No union");
    }

    for (Core.PermissionRelationshipTree child : union.getChildrenList()) {
      if (!child.hasLeaf()) {
        throw new RuntimeException("No leaf");
      }
      String groupPermission = child.getExpandedRelation();

      Core.DirectSubjectSet leaf = child.getLeaf();
      for (SubjectReference subject : leaf.getSubjectsList()) {
        memberList.add(
            new GroupSubject(
                subject.getObject().getObjectType(),
                subject.getObject().getObjectId(),
                groupPermission));
      }
    }

    return memberList;
  }

  public List<String> lookupResources(
      String subjectType, String subjectId, String resourceType, String permission) {

    var builder =
        LookupResourcesRequest.newBuilder()
            .setResourceObjectType(resourceType)
            .setSubject(
                SubjectReference.newBuilder()
                    .setObject(
                        ObjectReference.newBuilder()
                            .setObjectType(subjectType)
                            .setObjectId(subjectId)
                            .build())
                    .build())
            .setPermission(permission);

    // If zedToken isn't set yet, do a fully consistent request and store the
    // zedToken returned in the response (below)
    if (zedToken != null) {
      builder.setConsistency(Consistency.newBuilder().setAtLeastAsFresh(zedToken).build());
    } else {
      builder.setConsistency(Consistency.newBuilder().setFullyConsistent(true).build());
    }

    Iterator<LookupResourcesResponse> responseList;
    try {
      responseList = grpcPermissionsService.lookupResources(builder.build());
      List<String> resultList = new ArrayList<>();

      while (responseList.hasNext()) {
        LookupResourcesResponse response = responseList.next();
        resultList.add(response.getResourceObjectId());
        if (zedToken == null) {
          zedToken = response.getLookedUpAt();
        }
      }
      return resultList;
    } catch (Exception e) {
      logger.warn("RPC failed: {}", e.getMessage());
      throw new RuntimeException("Resource lookup failed", e);
    }
  }

  // Returns list of unique subject ids
  public Set<String> lookupSubjects(
      String resourceType,
      String resourceId,
      String permission,
      String subjectType,
      @Nullable String subjectRelation) {

    var builder =
      PermissionService.LookupSubjectsRequest.newBuilder()
        .setResource(
          ObjectReference.newBuilder()
            .setObjectType(resourceType)
            .setObjectId(resourceId)
            .build())
        .setPermission(permission)
        .setSubjectObjectType(subjectType);

    if (subjectRelation != null) {
      builder.setOptionalSubjectRelation(subjectRelation);
    }

    // If zedToken isn't set yet, do a fully consistent request and store the
    // zedToken returned in the response (below)
    if (zedToken != null) {
      builder.setConsistency(Consistency.newBuilder().setAtLeastAsFresh(zedToken).build());
    } else {
      builder.setConsistency(Consistency.newBuilder().setFullyConsistent(true).build());
    }

    Iterator<PermissionService.LookupSubjectsResponse> responseList;
    try {
      responseList = grpcPermissionsService.lookupSubjects(builder.build());
      Set<String> resultSet = new HashSet<>();

      while (responseList.hasNext()) {
        PermissionService.LookupSubjectsResponse response = responseList.next();
        resultSet.add(response.getSubject().getSubjectObjectId());
        if (zedToken == null) {
          zedToken = response.getLookedUpAt();
        }
      }
      return resultSet;
    } catch (Exception e) {
      logger.warn("RPC failed: {}", e.getMessage());
      throw new RuntimeException("Subject lookup failed", e);
    }
  }

  private String readSchemaFromResources() {
    try {
      // TODO: make this configuration
      URL url = Resources.getResource("spiceSchema.txt");
      return Resources.toString(url, StandardCharsets.UTF_8);
    } catch (IOException e) {
      logger.error("Failed to locate schema");
      throw new IllegalArgumentException("Failed to locate schema");
    }
  }
}
