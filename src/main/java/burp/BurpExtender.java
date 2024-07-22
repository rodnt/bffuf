package burp;

import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

import com.moandjiezana.toml.Toml;
import com.moandjiezana.toml.TomlWriter;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel configPanel;
    private JTextField[] wordlistFields = new JTextField[4];
    private JTextField sniperWordlistField;
    private String[] wordlists = new String[4];
    private String sniperWordlist;
    private JComboBox<String> protoBox;
    private JCheckBox requestProtoCheckBox, extensionCheckBox, delayCheckBox, replayProxyCheckBox, proxyUrlCheckBox, customCheckBox;
    private JCheckBox recursionCheckBox, silentModeCheckBox, verboseCheckBox, stopForbiddenCheckBox, followRedirectsCheckBox;
    private JTextField extensionsField, delayField, replayProxyField, proxyUrlField, customField;
    private JTextField customMarker1Field, customWordlist1Field, customMarker2Field, customWordlist2Field;
    private JTextArea logsTextArea;
    private String configFilePath;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.printOutput("Author: opcod3r github.com/rodnt\n ffuf author: github.com/ffuf/ffuf");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("bffuf");
        callbacks.registerContextMenuFactory(this);

        configFilePath = System.getProperty("user.home") + "/.config/bffuf/bffuf.config.toml";

        createConfigPanel();
        loadConfig();
        callbacks.addSuiteTab(this);
    }

    private void createConfigPanel() {
        configPanel = new JPanel(new BorderLayout());

        // Create tabs
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Configuration", createMainConfigPanel());
        tabbedPane.addTab("FFUF Logs", createLogsPanel());

        configPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createMainConfigPanel() {
        JPanel mainConfigPanel = new JPanel(new GridBagLayout());
        mainConfigPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 5, 5, 5);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;

        int row = 0;

        // Add checkboxes first
        recursionCheckBox = new JCheckBox("Recursion (-recursion)");
        c.gridx = 0;
        c.gridy = row++;
        mainConfigPanel.add(recursionCheckBox, c);

        silentModeCheckBox = new JCheckBox("Silent Mode (-s)");
        c.gridx = 0;
        c.gridy = row++;
        mainConfigPanel.add(silentModeCheckBox, c);

        verboseCheckBox = new JCheckBox("Verbose (-v)");
        c.gridx = 0;
        c.gridy = row++;
        mainConfigPanel.add(verboseCheckBox, c);

        stopForbiddenCheckBox = new JCheckBox("Stop on 403 Forbidden (-sf)");
        c.gridx = 0;
        c.gridy = row++;
        mainConfigPanel.add(stopForbiddenCheckBox, c);

        followRedirectsCheckBox = new JCheckBox("Follow Redirects (-r)");
        c.gridx = 0;
        c.gridy = row++;
        mainConfigPanel.add(followRedirectsCheckBox, c);

        requestProtoCheckBox = new JCheckBox("Request Proto");
        c.gridx = 0;
        c.gridy = row++;
        mainConfigPanel.add(requestProtoCheckBox, c);

        protoBox = new JComboBox<>(new String[]{"http", "https"});
        c.gridx = 1;
        mainConfigPanel.add(protoBox, c);

        extensionCheckBox = new JCheckBox("Add Extensions (-e)");
        c.gridx = 0;
        c.gridy = row++;
        mainConfigPanel.add(extensionCheckBox, c);

        extensionsField = new JTextField(20);
        c.gridx = 1;
        mainConfigPanel.add(extensionsField, c);

        delayCheckBox = new JCheckBox("Delay (-p)");
        c.gridx = 0;
        c.gridy = row++;
        mainConfigPanel.add(delayCheckBox, c);

        delayField = new JTextField(20);
        c.gridx = 1;
        mainConfigPanel.add(delayField, c);

        replayProxyCheckBox = new JCheckBox("Replay Proxy (-replay-proxy)");
        c.gridx = 0;
        c.gridy = row++;
        mainConfigPanel.add(replayProxyCheckBox, c);

        replayProxyField = new JTextField(20);
        c.gridx = 1;
        mainConfigPanel.add(replayProxyField, c);

        proxyUrlCheckBox = new JCheckBox("Proxy URL (-x)");
        c.gridx = 0;
        c.gridy = row++;
        mainConfigPanel.add(proxyUrlCheckBox, c);

        proxyUrlField = new JTextField(20);
        c.gridx = 1;
        mainConfigPanel.add(proxyUrlField, c);

        customCheckBox = new JCheckBox("Custom Parameters");
        c.gridx = 0;
        c.gridy = row++;
        mainConfigPanel.add(customCheckBox, c);

        customField = new JTextField(20);
        c.gridx = 1;
        mainConfigPanel.add(customField, c);

        // Add wordlists and other fields
        for (int i = 0; i < 4; i++) {
            c.gridx = 0;
            c.gridy = row;
            mainConfigPanel.add(new JLabel("Wordlist for FUZZ" + (i + 1)), c);

            wordlistFields[i] = new JTextField(20);
            c.gridx = 1;
            mainConfigPanel.add(wordlistFields[i], c);

            wordlistFields[i].setText("Click to choose wordlist...");
            final int index = i;
            wordlistFields[i].addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mouseClicked(java.awt.event.MouseEvent evt) {
                    chooseFile(wordlistFields[index]);
                }
            });

            row++;
        }

        c.gridx = 0;
        c.gridy = row;
        mainConfigPanel.add(new JLabel("SNIPER Wordlist"), c);

        sniperWordlistField = new JTextField(20);
        c.gridx = 1;
        mainConfigPanel.add(sniperWordlistField, c);

        sniperWordlistField.setText("Click to choose wordlist...");
        sniperWordlistField.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                chooseFile(sniperWordlistField);
            }
        });

        row++;
        c.gridx = 0;
        c.gridy = row;
        mainConfigPanel.add(new JLabel("Custom Marker 1"), c);

        customMarker1Field = new JTextField(10);
        c.gridx = 1;
        mainConfigPanel.add(customMarker1Field, c);

        customMarker1Field.setText("Enter custom marker...");

        row++;
        c.gridx = 0;
        c.gridy = row;
        mainConfigPanel.add(new JLabel("Custom Wordlist 1"), c);

        customWordlist1Field = new JTextField(20);
        c.gridx = 1;
        mainConfigPanel.add(customWordlist1Field, c);

        customWordlist1Field.setText("Click to choose wordlist...");
        customWordlist1Field.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                chooseFile(customWordlist1Field);
            }
        });

        row++;
        c.gridx = 0;
        c.gridy = row;
        mainConfigPanel.add(new JLabel("Custom Marker 2"), c);

        customMarker2Field = new JTextField(10);
        c.gridx = 1;
        mainConfigPanel.add(customMarker2Field, c);

        customMarker2Field.setText("Enter custom marker...");

        row++;
        c.gridx = 0;
        c.gridy = row;
        mainConfigPanel.add(new JLabel("Custom Wordlist 2"), c);

        customWordlist2Field = new JTextField(20);
        c.gridx = 1;
        mainConfigPanel.add(customWordlist2Field, c);

        customWordlist2Field.setText("Click to choose wordlist...");
        customWordlist2Field.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                chooseFile(customWordlist2Field);
            }
        });

        // Add clear saved requests button
        row++;
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 2;
        JButton clearButton = new JButton("Clear Saved Requests");
        clearButton.addActionListener(e -> clearSavedRequests());
        mainConfigPanel.add(clearButton, c);
        c.gridwidth = 1;

        row++;
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 2;
        JButton saveButton = new JButton("Save Configuration");
        saveButton.addActionListener(e -> saveConfig());
        mainConfigPanel.add(saveButton, c);

        return mainConfigPanel;
    }

    private JPanel createLogsPanel() {
        JPanel logsPanel = new JPanel(new BorderLayout());
        logsTextArea = new JTextArea();
        logsTextArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logsTextArea);
        logsPanel.add(scrollPane, BorderLayout.CENTER);

        JButton clearLogsButton = new JButton("Clear Logs");
        clearLogsButton.addActionListener(e -> clearLogs());
        logsPanel.add(clearLogsButton, BorderLayout.SOUTH);

        return logsPanel;
    }

    private void chooseFile(JTextField textField) {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            textField.setText(selectedFile.getAbsolutePath());
        }
    }

    private void clearSavedRequests() {
        int response = JOptionPane.showConfirmDialog(configPanel, "Are you sure you want to clear all saved requests?", "Confirm", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (response == JOptionPane.YES_OPTION) {
            String home = System.getProperty("user.home");
            File dir = new File(home + "/.config/bffuf/tmp/");
            if (dir.exists() && dir.isDirectory()) {
                for (File file : Objects.requireNonNull(dir.listFiles())) {
                    if (!file.isDirectory()) {
                        file.delete();
                    }
                }
                JOptionPane.showMessageDialog(configPanel, "All saved requests have been cleared.", "Information", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private void loadConfig() {
        try {
            File file = new File(configFilePath);
            if (!file.exists()) {
                file.getParentFile().mkdirs();
                file.createNewFile();
            }

            Toml toml = new Toml().read(file);
            for (int i = 0; i < 4; i++) {
                wordlistFields[i].setText(toml.getString("wordlist" + (i + 1), ""));
            }
            sniperWordlistField.setText(toml.getString("sniperWordlist", ""));
            customMarker1Field.setText(toml.getString("customMarker1", ""));
            customWordlist1Field.setText(toml.getString("customWordlist1", ""));
            customMarker2Field.setText(toml.getString("customMarker2", ""));
            customWordlist2Field.setText(toml.getString("customWordlist2", ""));
        } catch (IOException e) {
            callbacks.printError("Failed to load configuration: " + e.getMessage());
        }
    }

    private void saveConfig() {
        try {
            Map<String, Object> data = new HashMap<>();
            for (int i = 0; i < 4; i++) {
                data.put("wordlist" + (i + 1), wordlistFields[i].getText());
            }
            data.put("sniperWordlist", sniperWordlistField.getText());
            data.put("customMarker1", customMarker1Field.getText());
            data.put("customWordlist1", customWordlist1Field.getText());
            data.put("customMarker2", customMarker2Field.getText());
            data.put("customWordlist2", customWordlist2Field.getText());

            TomlWriter tomlWriter = new TomlWriter();
            tomlWriter.write(data, new File(configFilePath));
            callbacks.printOutput("Configuration saved successfully.");
        } catch (IOException e) {
            callbacks.printError("Failed to save configuration: " + e.getMessage());
        }
    }

    private void clearLogs() {
        int response = JOptionPane.showConfirmDialog(configPanel, "Are you sure you want to clear all logs?", "Confirm", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (response == JOptionPane.YES_OPTION) {
            String home = System.getProperty("user.home");
            File dir = new File(home + "/.config/bffuf/logs/");
            if (dir.exists() && dir.isDirectory()) {
                for (File file : Objects.requireNonNull(dir.listFiles())) {
                    if (!file.isDirectory()) {
                        file.delete();
                    }
                }
                logsTextArea.setText("");
                JOptionPane.showMessageDialog(configPanel, "All logs have been cleared.", "Information", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private void updateLogs(String logMessage) {
        SwingUtilities.invokeLater(() -> logsTextArea.append(logMessage + "\n"));
    }

    @Override
    public String getTabCaption() {
        return "bffuf Config";
    }

    @Override
    public Component getUiComponent() {
        return configPanel;
    }

    @Override
    public java.util.List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        java.util.List<JMenuItem> menuItems = new ArrayList<>();
        JMenu bfffufMenu = new JMenu("bfffuf");

        JMenuItem clusterBomb = new JMenuItem("Cluster Bomb");
        clusterBomb.addActionListener(new FFUFActionListener(invocation, "clusterbomb"));
        bfffufMenu.add(clusterBomb);

        JMenuItem pitchfork = new JMenuItem("Pitchfork");
        pitchfork.addActionListener(new FFUFActionListener(invocation, "pitchfork"));
        bfffufMenu.add(pitchfork);

        JMenuItem sniper = new JMenuItem("Sniper");
        sniper.addActionListener(new FFUFActionListener(invocation, "sniper"));
        bfffufMenu.add(sniper);

        menuItems.add(bfffufMenu);
        return menuItems;
    }

    private class FFUFActionListener implements ActionListener {
        private final IContextMenuInvocation invocation;
        private final String mode;

        public FFUFActionListener(IContextMenuInvocation invocation, String mode) {
            this.invocation = invocation;
            this.mode = mode;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    IHttpRequestResponse message = messages[0];
                    byte[] request = message.getRequest();
                    String requestString = new String(request);
                    String host = message.getHttpService().getHost();

                    List<String> fuzzMarkers = new ArrayList<>();
                    for (int i = 1; i <= 4; i++) {
                        if (requestString.contains("FUZZ" + i)) {
                            fuzzMarkers.add("FUZZ" + i);
                            callbacks.printOutput("Found marker: FUZZ" + i);
                        }
                    }

                    if (customMarker1Field.getText() != null && !customMarker1Field.getText().isEmpty()) {
                        String customMarker1 = customMarker1Field.getText();
                        if (requestString.contains(customMarker1)) {
                            fuzzMarkers.add(customMarker1);
                        }
                    }

                    if (customMarker2Field.getText() != null && !customMarker2Field.getText().isEmpty()) {
                        String customMarker2 = customMarker2Field.getText();
                        if (requestString.contains(customMarker2)) {
                            fuzzMarkers.add(customMarker2);
                        }
                    }

                    boolean sniperMarkerFound = false;
                    if (mode.equals("sniper") && requestString.contains("SNIPER")) {
                        requestString = requestString.replace("SNIPER", "§§");
                        sniperMarkerFound = true;
                    }

                    if (mode.equals("sniper") && requestString.contains("§§")) {
                        sniperMarkerFound = true;
                    }

                    String requestFilePath = saveRequestToFile(requestString, host);
                    callbacks.printOutput("Request saved to: " + requestFilePath);
                    executeFFUF(requestFilePath, fuzzMarkers, sniperMarkerFound, mode, host);
                }
            } catch (Exception ex) {
                callbacks.issueAlert("Error executing FFUF: " + ex.getMessage());
            }
        }

        private String saveRequestToFile(String requestString, String host) throws IOException {
            String home = System.getProperty("user.home");
            File dir = new File(home + "/.config/bffuf/tmp/");
            if (!dir.exists()) {
                dir.mkdirs();
            }
            String date = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            String requestFileName = "request_" + host + "_" + date + ".txt";
            File requestFile = new File(dir, requestFileName);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(requestFile))) {
                writer.write(requestString);
            }
            return requestFile.getAbsolutePath();
        }

        private void executeFFUF(String requestFilePath, List<String> fuzzMarkers, boolean sniperMarkerFound, String mode, String host) throws IOException {
            List<String> command = new ArrayList<>();
            command.add("ffuf");

            boolean wordlistAdded = false;
            if (sniperMarkerFound && sniperWordlistField.getText() != null && !sniperWordlistField.getText().isEmpty()) {
                command.add("-w");
                command.add(sniperWordlistField.getText());
                callbacks.printOutput("Adding sniper wordlist: " + sniperWordlistField.getText());
                wordlistAdded = true;
            } else {
                for (int i = 0; i < fuzzMarkers.size(); i++) {
                    if (i < 4 && wordlistFields[i].getText() != null && !wordlistFields[i].getText().isEmpty()) {
                        command.add("-w");
                        command.add(wordlistFields[i].getText() + ":" + fuzzMarkers.get(i));
                        callbacks.printOutput("Adding wordlist: " + wordlistFields[i].getText() + " for marker: " + fuzzMarkers.get(i));
                        wordlistAdded = true;
                    } else if (fuzzMarkers.get(i).equals(customMarker1Field.getText()) && customWordlist1Field.getText() != null && !customWordlist1Field.getText().isEmpty()) {
                        command.add("-w");
                        command.add(customWordlist1Field.getText() + ":" + customMarker1Field.getText());
                        callbacks.printOutput("Adding custom wordlist 1: " + customWordlist1Field.getText() + " for marker: " + customMarker1Field.getText());
                        wordlistAdded = true;
                    } else if (fuzzMarkers.get(i).equals(customMarker2Field.getText()) && customWordlist2Field.getText() != null && !customWordlist2Field.getText().isEmpty()) {
                        command.add("-w");
                        command.add(customWordlist2Field.getText() + ":" + customMarker2Field.getText());
                        callbacks.printOutput("Adding custom wordlist 2: " + customWordlist2Field.getText() + " for marker: " + customMarker2Field.getText());
                        wordlistAdded = true;
                    }
                }
            }

            if (!wordlistAdded) {
                callbacks.printOutput("No wordlists were added to the command.");
            } else {
                callbacks.printOutput("Wordlists added to the command.");
            }

            command.add("-request");
            command.add(requestFilePath);
            command.add("-mode");
            command.add(mode);

            if (requestProtoCheckBox.isSelected()) {
                command.add("-request-proto");
                command.add((String) protoBox.getSelectedItem());
            }

            if (extensionCheckBox.isSelected()) {
                command.add("-e");
                command.add(extensionsField.getText().trim());
            }

            if (delayCheckBox.isSelected()) {
                command.add("-p");
                command.add(delayField.getText().trim());
            }

            if (replayProxyCheckBox.isSelected()) {
                command.add("-replay-proxy");
                command.add(replayProxyField.getText().trim());
            }

            if (proxyUrlCheckBox.isSelected()) {
                command.add("-x");
                command.add(proxyUrlField.getText().trim());
            }

            if (recursionCheckBox.isSelected()) {
                command.add("-recursion (add the FUZZ word to the repeater/intruder)");
            }

            if (silentModeCheckBox.isSelected()) {
                command.add("-s");
            }

            if (verboseCheckBox.isSelected()) {
                command.add("-v");
            }

            if (stopForbiddenCheckBox.isSelected()) {
                command.add("-sf");
            }

            if (followRedirectsCheckBox.isSelected()) {
                command.add("-r");
            }

            if (customCheckBox.isSelected()) {
                String[] customParams = customField.getText().trim().split(" ");
                for (String param : customParams) {
                    command.add(param);
                }
            }

            String commandString = String.join(" ", command);
            callbacks.printOutput("Executing command: " + commandString);

            String[] cmdArray;
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("mac")) {
                cmdArray = new String[]{"/usr/bin/osascript", "-e", "tell application \"Terminal\" to do script \"" + commandString + "\""};
            } else if (os.contains("nix") || os.contains("nux")) {
                cmdArray = new String[]{"x-terminal-emulator", "-e", "bash -c '" + commandString + "; exec bash'"};
            } else {
                throw new IOException("Unsupported OS: " + os);
            }

            ProcessBuilder processBuilder = new ProcessBuilder(cmdArray);
            processBuilder.redirectErrorStream(true); // Combine stdout and stderr
            Process process = processBuilder.start();

            new Thread(() -> {
                try {
                    File logDir = new File(System.getProperty("user.home") + "/.config/bffuf/logs/");
                    if (!logDir.exists()) {
                        logDir.mkdirs();
                    }
                    String logFileName = host + "_" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date()) + ".log";
                    File logFile = new File(logDir, logFileName);

                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                         BufferedWriter logWriter = new BufferedWriter(new FileWriter(logFile))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            logWriter.write(line);
                            logWriter.newLine();
                            updateLogs(line);
                        }
                    }

                    process.waitFor();
                    createBurpIssue(host);
                } catch (InterruptedException | IOException ex) {
                    callbacks.printError("Error waiting for FFUF process: " + ex.getMessage());
                }
            }).start();
        }

        private void createBurpIssue(String host) {
            try {
                URL url = new URL("http://" + host);
                IHttpService httpService = helpers.buildHttpService(host, 80, "http");
                byte[] request = helpers.buildHttpRequest(url);
                IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(httpService, request);
                IScanIssue issue = new CustomScanIssue(
                        httpService,
                        helpers.analyzeRequest(requestResponse).getUrl(),
                        new IHttpRequestResponse[]{requestResponse},
                        "FFUF Execution Complete",
                        "FFUF has finished executing on this domain.",
                        "Information");

                callbacks.addScanIssue(issue);
            } catch (MalformedURLException e) {
                callbacks.printError("Failed to create URL: " + e.getMessage());
            }
        }
    }

    private static class CustomScanIssue implements IScanIssue {
        private final IHttpService httpService;
        private final URL url;
        private final IHttpRequestResponse[] httpMessages;
        private final String name;
        private final String detail;
        private final String severity;

        public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity) {
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.name = name;
            this.detail = detail;
            this.severity = severity;
        }

        @Override
        public URL getUrl() {
            return url;
        }

        @Override
        public String getIssueName() {
            return name;
        }

        @Override
        public int getIssueType() {
            return 0;
        }

        @Override
        public String getSeverity() {
            return severity;
        }

        @Override
        public String getConfidence() {
            return "Certain";
        }

        @Override
        public String getIssueBackground() {
            return null;
        }

        @Override
        public String getRemediationBackground() {
            return null;
        }

        @Override
        public String getIssueDetail() {
            return detail;
        }

        @Override
        public String getRemediationDetail() {
            return null;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return httpMessages;
        }

        @Override
        public IHttpService getHttpService() {
            return httpService;
        }
    }
}