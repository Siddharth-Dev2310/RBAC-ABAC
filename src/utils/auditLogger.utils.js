import { AuditLog } from "../models/auditLog.models.js";

/**
 * 📝 Log an audit event
 * @param {Object} eventData - Event data to log
 * @param {string} eventData.userId - User ID performing the action
 * @param {string} eventData.action - Action being performed
 * @param {string} eventData.resource - Resource being accessed
 * @param {string} eventData.resourceType - Type of resource (optional)
 * @param {string} eventData.status - "allowed" or "denied"
 * @param {string} eventData.reason - Reason for the decision (optional)
 * @param {Object} eventData.metadata - Additional metadata (optional)
 * @param {string} eventData.ipAddress - IP address (optional)
 * @param {string} eventData.userAgent - User agent (optional)
 */
export const logAuditEvent = async (eventData) => {
  console.log(eventData);
  
  try {
    // Validate required fields
    if (!eventData.userId || !eventData.action || !eventData.resource || !eventData.status) {
      console.error("❌ Missing required fields for audit log:", {
        userId: !!eventData.userId,
        action: !!eventData.action,
        resource: !!eventData.resource,
        status: !!eventData.status
      });
      return null;
    }

    const auditLog = new AuditLog({
      userId: eventData.userId,
      action: eventData.action,
      resource: eventData.resource,
      resourceType: eventData.resourceType,
      status: eventData.status,
      reason: eventData.reason,
      metadata: eventData.metadata || {},
      ipAddress: eventData.ipAddress,
      userAgent: eventData.userAgent,
      timestamp: new Date(),
    });

    await auditLog.save();

    // Optional: Log to console in development
    if (process.env.NODE_ENV === "development") {
      console.log(
        `🔍 AUDIT: ${eventData.status.toUpperCase()} - ${eventData.action} on ${eventData.resource} by ${eventData.userId}`
      );
    }

    return auditLog;
  } catch (error) {
    console.error("❌ Error logging audit event:", error);
    // Don't throw error - audit logging should not break the main flow
    return null;
  }
};

/**
 * 📊 Get audit logs with filtering
 * @param {Object} filters - Filter options
 * @param {string} filters.userId - Filter by user ID
 * @param {string} filters.action - Filter by action
 * @param {string} filters.resource - Filter by resource
 * @param {string} filters.status - Filter by status
 * @param {Date} filters.startDate - Start date for range
 * @param {Date} filters.endDate - End date for range
 * @param {number} filters.page - Page number
 * @param {number} filters.limit - Results per page
 */
export const getAuditLogs = async (filters = {}) => {
  try {
    const {
      userId,
      action,
      resource,
      resourceType,
      status,
      startDate,
      endDate,
      page = 1,
      limit = 50,
    } = filters;

    const query = {};

    if (userId) query.userId = userId;
    if (action) query.action = action;
    if (resource) query.resource = resource;
    if (resourceType) query.resourceType = resourceType;
    if (status) query.status = status;

    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = new Date(startDate);
      if (endDate) query.timestamp.$lte = new Date(endDate);
    }

    const skip = (page - 1) * limit;

    const logs = await AuditLog.find(query)
      .populate("userId", "username email role")
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit);

    const total = await AuditLog.countDocuments(query);

    return {
      logs,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalLogs: total,
        limit,
      },
    };
  } catch (error) {
    console.error("❌ Error retrieving audit logs:", error);
    throw error;
  }
};

/**
 * 📈 Get audit statistics
 * @param {Object} filters - Filter options (userId, startDate, endDate)
 */
export const getAuditStatistics = async (filters = {}) => {
  try {
    const { userId, startDate, endDate } = filters;

    const matchQuery = {};
    if (userId) matchQuery.userId = userId;
    if (startDate || endDate) {
      matchQuery.timestamp = {};
      if (startDate) matchQuery.timestamp.$gte = new Date(startDate);
      if (endDate) matchQuery.timestamp.$lte = new Date(endDate);
    }

    const stats = await AuditLog.aggregate([
      { $match: matchQuery },
      {
        $facet: {
          byStatus: [
            {
              $group: {
                _id: "$status",
                count: { $sum: 1 },
              },
            },
          ],
          byAction: [
            {
              $group: {
                _id: "$action",
                count: { $sum: 1 },
              },
            },
            { $sort: { count: -1 } },
            { $limit: 10 },
          ],
          byResourceType: [
            {
              $group: {
                _id: "$resourceType",
                count: { $sum: 1 },
              },
            },
            { $sort: { count: -1 } },
          ],
          total: [
            {
              $count: "total",
            },
          ],
        },
      },
    ]);

    return {
      byStatus: stats[0].byStatus,
      byAction: stats[0].byAction,
      byResourceType: stats[0].byResourceType,
      total: stats[0].total[0]?.total || 0,
    };
  } catch (error) {
    console.error("❌ Error getting audit statistics:", error);
    throw error;
  }
};

/**
 * 🗑️ Clean old audit logs
 * @param {number} daysToKeep - Number of days to keep logs (default: 90)
 */
export const cleanOldAuditLogs = async (daysToKeep = 90) => {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

    const result = await AuditLog.deleteMany({
      timestamp: { $lt: cutoffDate },
    });

    console.log(
      `🧹 Cleaned ${result.deletedCount} audit logs older than ${daysToKeep} days`
    );
    return result.deletedCount;
  } catch (error) {
    console.error("❌ Error cleaning audit logs:", error);
    throw error;
  }
};

/**
 * 🔍 Get user activity summary
 * @param {string} userId - User ID
 * @param {number} days - Number of days to look back (default: 30)
 */
export const getUserActivitySummary = async (userId, days = 30) => {
  try {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const summary = await AuditLog.aggregate([
      {
        $match: {
          userId: userId,
          timestamp: { $gte: startDate },
        },
      },
      {
        $facet: {
          totalActions: [{ $count: "count" }],
          allowedActions: [
            { $match: { status: "allowed" } },
            { $count: "count" },
          ],
          deniedActions: [
            { $match: { status: "denied" } },
            { $count: "count" },
          ],
          actionBreakdown: [
            {
              $group: {
                _id: "$action",
                count: { $sum: 1 },
              },
            },
            { $sort: { count: -1 } },
          ],
          resourceBreakdown: [
            {
              $group: {
                _id: "$resourceType",
                count: { $sum: 1 },
              },
            },
            { $sort: { count: -1 } },
          ],
          recentActivity: [
            { $sort: { timestamp: -1 } },
            { $limit: 10 },
            {
              $project: {
                action: 1,
                resource: 1,
                status: 1,
                timestamp: 1,
              },
            },
          ],
        },
      },
    ]);

    return {
      totalActions: summary[0].totalActions[0]?.count || 0,
      allowedActions: summary[0].allowedActions[0]?.count || 0,
      deniedActions: summary[0].deniedActions[0]?.count || 0,
      actionBreakdown: summary[0].actionBreakdown,
      resourceBreakdown: summary[0].resourceBreakdown,
      recentActivity: summary[0].recentActivity,
      period: `Last ${days} days`,
    };
  } catch (error) {
    console.error("❌ Error getting user activity summary:", error);
    throw error;
  }
};

/**
 * 🚨 Detect suspicious activity
 * @param {string} userId - User ID
 * @param {number} threshold - Number of denied actions that trigger alert (default: 5)
 * @param {number} minutes - Time window in minutes (default: 10)
 */
export const detectSuspiciousActivity = async (
  userId,
  threshold = 5,
  minutes = 10
) => {
  try {
    const startTime = new Date();
    startTime.setMinutes(startTime.getMinutes() - minutes);

    const deniedCount = await AuditLog.countDocuments({
      userId: userId,
      status: "denied",
      timestamp: { $gte: startTime },
    });

    const isSuspicious = deniedCount >= threshold;

    if (isSuspicious) {
      console.warn(
        `🚨 SUSPICIOUS ACTIVITY: User ${userId} has ${deniedCount} denied actions in the last ${minutes} minutes`
      );
    }

    return {
      isSuspicious,
      deniedCount,
      threshold,
      timeWindow: `${minutes} minutes`,
    };
  } catch (error) {
    console.error("❌ Error detecting suspicious activity:", error);
    throw error;
  }
};

export default {
  logAuditEvent,
  getAuditLogs,
  getAuditStatistics,
  cleanOldAuditLogs,
  getUserActivitySummary,
  detectSuspiciousActivity,
};
