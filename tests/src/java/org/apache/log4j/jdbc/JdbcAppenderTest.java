/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.jdbc;

import junit.framework.TestCase;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.NDC;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.VectorErrorHandler;
import org.apache.log4j.xml.XLevel;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class JdbcAppenderTest extends TestCase {
    private static final String DB_URL = "jdbc:h2:mem:test_db";

    // Closing the last connection to "in-memory h2" removes the database
    // So we keep the connection during the test
    // The logger opens its own connection
    Connection con;

    Logger logger = Logger.getLogger(JdbcAppenderTest.class);

    public JdbcAppenderTest(final String name) {
        super(name);
    }

    public void setUp() throws SQLException {
        try {
            // Explicitly load the H2 driver
            Class.forName("org.h2.Driver");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("H2 Driver not found in classpath", e);
        }

        con = DriverManager.getConnection(DB_URL);
        Statement st = con.createStatement();
        try {
            st.execute(
                    "create table logs(level varchar(100),location varchar(100),message varchar(100),message2 varchar(100))");
        } finally {
            st.close();
        }
    }

    public void tearDown() throws SQLException {
        LogManager.shutdown();
        con.close();
    }

    public void testVerifyJdbcBufferSize1() throws SQLException {
        PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");

        String oldThreadName = Thread.currentThread().getName();
        try {
            Thread.currentThread().setName("main");
            logger.debug("message with ' quote");
            assertEquals("batchSize=1, so messages should be added immediately",
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
                    joinSorted(getMessagesFromDababase()));

            logger.fatal("message with \" quote");

            assertEquals("batchSize=1, so two messages should be in DB after two logging calls",
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
                            + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL message with \" quote\n",
                    joinSorted(getMessagesFromDababase()));
        } finally {
            Thread.currentThread().setName(oldThreadName);
        }
    }

    public void testVerifyJdbcBufferSize2() throws SQLException {
        PropertyConfigurator.configure("input/jdbc_h2_bufferSize2.properties");

        String oldThreadName = Thread.currentThread().getName();
        try {
            Thread.currentThread().setName("main");
            logger.log(XLevel.TRACE, "xtrace message");
            logger.debug("message with ' quote");
            logger.info("message with \" quote");
            logger.warn("?");
            // bufferSize=2, so this messsage won't yet be stored to the db
            logger.error("m4");

            assertEquals(
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
                            + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
                            + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
                            + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
                    joinSorted(getMessagesFromDababase()));

            logger.fatal("m5");

            assertEquals("Logging m5 message should trigger buffer flush for both m4 and m5",
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
                            + "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; m4;  org.apache.log4j.jdbc.JdbcAppenderTest ERROR m4\n"
                            + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; m5;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL m5\n"
                            + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
                            + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
                            + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
                    joinSorted(getMessagesFromDababase()));
        } finally {
            Thread.currentThread().setName(oldThreadName);
        }
    }

    /**
     * CVE-2022-23305: a logged message (%m) must not be able to change the
     * INSERT statement. Before the fix the payload closed the '%m' literal,
     * supplied its own value for the last column and commented out the rest.
     */
    public void testMessageCannotInjectSql() throws SQLException {
        PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");
        VectorErrorHandler errorHandler = new VectorErrorHandler();
        LogManager.getRootLogger().getAppender("A").setErrorHandler(errorHandler);

        String payload = "pwned', 'INJECTED') -- ";
        logger.error(payload);

        assertEquals("message must be stored verbatim, not interpreted as SQL",
                "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; " + payload
                        + ";  org.apache.log4j.jdbc.JdbcAppenderTest ERROR " + payload + "\n",
                joinSorted(getMessagesFromDababase()));
        assertEquals(0, errorHandler.size());
    }

    /**
     * CVE-2022-23305: a logged message must not be able to append a second
     * (stacked) SQL statement, also when the events are written as a batch.
     */
    public void testMessageCannotRunStackedStatement() throws SQLException {
        PropertyConfigurator.configure("input/jdbc_h2_bufferSize2.properties");
        VectorErrorHandler errorHandler = new VectorErrorHandler();
        LogManager.getRootLogger().getAppender("A").setErrorHandler(errorHandler);

        String payload = "x', 'y'); delete from logs; --";
        logger.info("first");
        logger.info("second");
        logger.warn("third");
        logger.warn(payload);

        assertEquals("the stacked 'delete from logs' statement must not be executed",
                "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; first;  org.apache.log4j.jdbc.JdbcAppenderTest INFO first\n"
                        + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; second;  org.apache.log4j.jdbc.JdbcAppenderTest INFO second\n"
                        + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; third;  org.apache.log4j.jdbc.JdbcAppenderTest WARN third\n"
                        + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; " + payload
                        + ";  org.apache.log4j.jdbc.JdbcAppenderTest WARN " + payload + "\n",
                joinSorted(getMessagesFromDababase()));
        assertEquals(0, errorHandler.size());
    }

    /**
     * CVE-2022-23305: a value put in the MDC (%X) must not be able to change
     * the INSERT statement.
     */
    public void testMdcValueCannotInjectSql() throws SQLException {
        VectorErrorHandler errorHandler = configureAppender(
                "insert into logs(level,location,message,message2) values('%X{user}','%p','%c','%m')");

        String payload = "admin', 'INJECTED', 'INJECTED', 'INJECTED') -- ";
        MDC.put("user", payload);
        try {
            logger.info("login");
        } finally {
            MDC.remove("user");
        }

        assertEquals("MDC value must be stored verbatim, not interpreted as SQL",
                payload + "; INFO; org.apache.log4j.jdbc.JdbcAppenderTest; login\n",
                joinSorted(getMessagesFromDababase()));
        assertEquals(0, errorHandler.size());
    }

    /**
     * CVE-2022-23305: a value pushed on the NDC (%x) must not be able to
     * change the INSERT statement.
     */
    public void testNdcValueCannotInjectSql() throws SQLException {
        VectorErrorHandler errorHandler = configureAppender(
                "insert into logs(level,location,message,message2) values('%p','%x','%c','%m')");

        String payload = "ndc', 'INJECTED', 'INJECTED') -- ";
        NDC.push(payload);
        try {
            logger.info("request");
        } finally {
            NDC.clear();
            NDC.remove();
        }

        assertEquals("NDC value must be stored verbatim, not interpreted as SQL",
                "INFO; " + payload + "; org.apache.log4j.jdbc.JdbcAppenderTest; request\n",
                joinSorted(getMessagesFromDababase()));
        assertEquals(0, errorHandler.size());
    }

    /**
     * CVE-2022-23305: a thread name (%t) must not be able to change the
     * INSERT statement.
     */
    public void testThreadNameCannotInjectSql() throws SQLException {
        VectorErrorHandler errorHandler = configureAppender(
                "insert into logs(level,location,message,message2) values('%p','%c','%t','%m')");

        String payload = "worker', 'INJECTED') -- ";
        String oldThreadName = Thread.currentThread().getName();
        try {
            Thread.currentThread().setName(payload);
            logger.info("job");
        } finally {
            Thread.currentThread().setName(oldThreadName);
        }

        assertEquals("thread name must be stored verbatim, not interpreted as SQL",
                "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; " + payload + "; job\n",
                joinSorted(getMessagesFromDababase()));
        assertEquals(0, errorHandler.size());
    }

    private VectorErrorHandler configureAppender(String sql) {
        LogManager.resetConfiguration();
        JDBCAppender appender = new JDBCAppender();
        appender.setName("B");
        appender.setURL(DB_URL);
        appender.setUser("");
        appender.setPassword("");
        appender.setSql(sql);
        VectorErrorHandler errorHandler = new VectorErrorHandler();
        appender.setErrorHandler(errorHandler);
        appender.activateOptions();
        Logger.getRootLogger().addAppender(appender);
        return errorHandler;
    }

    private static String joinSorted(List list) {
        Collections.sort(list);
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < list.size(); i++) {
            String s = (String) list.get(i);
            sb.append(s).append('\n');
        }
        return sb.toString();
    }

    private List getMessagesFromDababase() throws SQLException {
        List res = new ArrayList();
        PreparedStatement ps = con.prepareStatement("select level,location,message,message2 from logs");
        try {
            ResultSet rs = ps.executeQuery();
            try {
                while (rs.next()) {
                    res.add(rs.getString(1) + "; " + rs.getString(2) + "; " + rs.getString(3) + "; "
                            + rs.getString(4));
                }
            } finally {
                rs.close();
            }
        } finally {
            ps.close();
        }
        return res;
    }
}
