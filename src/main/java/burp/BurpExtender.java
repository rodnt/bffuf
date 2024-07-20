package burp;

import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import com.moandjiezana.toml.Toml;
import com.moandjiezana.toml.TomlWriter;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ITab {
    private IBurpExtenderCallbacks callbacks;
    private JPanel configPanel;
    private JTextField[] wordlistFields = new JTextField[4];
    private JTextField sniperWordlistField;
    private String[] wordlists = new String[4];
    private String sniperWordlist;
    private JComboBox<String> protoBox;
    private JCheckBox requestProtoCheckBox, extensionCheckBox, delayCheckBox, replayProxyCheckBox, proxyUrlCheckBox, customCheckBox;
    private JCheckBox recursionCheckBox, silentModeCheckBox, verboseCheckBox, stopForbiddenCheckBox, followRedirectsCheckBox;
    private JTextField extensionsField, delayField, replayProxyField, proxyUrlField, customField;
    private String configFilePath;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.printOutput("Author: opcod3r - github.com/rodnt");
        callbacks.setExtensionName("bffuf");
        callbacks.registerContextMenuFactory(this);

        configFilePath = System.getProperty("user.home") + "/.config/bffuf/bffuf.config.toml";

        // Cria o painel de configuração antes de adicionar a aba
        createConfigPanel();
        loadConfig();
        callbacks.addSuiteTab(this);
    }

    private void createConfigPanel() {
        configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 5, 5, 5);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;

        int row = 0;

        // Add clear button first
        JButton clearButton = new JButton("Clear Saved Requests");
        clearButton.addActionListener(e -> clearSavedRequests());
        c.gridx = 0;
        c.gridy = row++;
        c.gridwidth = 2;
        configPanel.add(clearButton, c);
        c.gridwidth = 1;

        // Add checkboxes next
        recursionCheckBox = new JCheckBox("Recursion (-recursion)");
        c.gridx = 0;
        c.gridy = row++;
        configPanel.add(recursionCheckBox, c);

        silentModeCheckBox = new JCheckBox("Silent Mode (-s)");
        c.gridx = 0;
        c.gridy = row++;
        configPanel.add(silentModeCheckBox, c);

        verboseCheckBox = new JCheckBox("Verbose (-v)");
        c.gridx = 0;
        c.gridy = row++;
        configPanel.add(verboseCheckBox, c);

        stopForbiddenCheckBox = new JCheckBox("Stop on 403 Forbidden (-sf)");
        c.gridx = 0;
        c.gridy = row++;
        configPanel.add(stopForbiddenCheckBox, c);

        followRedirectsCheckBox = new JCheckBox("Follow Redirects (-r)");
        c.gridx = 0;
        c.gridy = row++;
        configPanel.add(followRedirectsCheckBox, c);

        // Add wordlists and other fields
        for (int i = 0; i < 4; i++) {
            c.gridx = 0;
            c.gridy = row;
            configPanel.add(new JLabel("Wordlist for FUZZ" + (i + 1)), c);

            wordlistFields[i] = new JTextField(20);
            c.gridx = 1;
            configPanel.add(wordlistFields[i], c);

            JButton browseButton = new JButton("Browse...");
            browseButton.setPreferredSize(new Dimension(100, 25));
            final int index = i;
            browseButton.addActionListener(e -> chooseFile(wordlistFields[index]));
            c.gridx = 2;
            configPanel.add(browseButton, c);

            row++;
        }

        c.gridx = 0;
        c.gridy = row;
        configPanel.add(new JLabel("SNIPER Wordlist"), c);

        sniperWordlistField = new JTextField(20);
        c.gridx = 1;
        configPanel.add(sniperWordlistField, c);

        JButton sniperBrowseButton = new JButton("Browse...");
        sniperBrowseButton.setPreferredSize(new Dimension(100, 25));
        sniperBrowseButton.addActionListener(e -> chooseFile(sniperWordlistField));
        c.gridx = 2;
        configPanel.add(sniperBrowseButton, c);

        row++;
        c.gridx = 0;
        c.gridy = row;
        requestProtoCheckBox = new JCheckBox("Request Proto");
        configPanel.add(requestProtoCheckBox, c);

        protoBox = new JComboBox<>(new String[]{"http", "https"});
        c.gridx = 1;
        configPanel.add(protoBox, c);

        row++;
        c.gridx = 0;
        c.gridy = row;
        extensionCheckBox = new JCheckBox("Add Extensions (-D -e)");
        configPanel.add(extensionCheckBox, c);

        extensionsField = new JTextField(20);
        c.gridx = 1;
        configPanel.add(extensionsField, c);

        row++;
        c.gridx = 0;
        c.gridy = row;
        delayCheckBox = new JCheckBox("Delay (-p)");
        configPanel.add(delayCheckBox, c);

        delayField = new JTextField(20);
        c.gridx = 1;
        configPanel.add(delayField, c);

        row++;
        c.gridx = 0;
        c.gridy = row;
        replayProxyCheckBox = new JCheckBox("Replay Proxy (-replay-proxy)");
        configPanel.add(replayProxyCheckBox, c);

        replayProxyField = new JTextField(20);
        c.gridx = 1;
        configPanel.add(replayProxyField, c);

        row++;
        c.gridx = 0;
        c.gridy = row;
        proxyUrlCheckBox = new JCheckBox("Proxy URL (-x)");
        configPanel.add(proxyUrlCheckBox, c);

        proxyUrlField = new JTextField(20);
        c.gridx = 1;
        configPanel.add(proxyUrlField, c);

        row++;
        c.gridx = 0;
        c.gridy = row;
        customCheckBox = new JCheckBox("Custom Parameters");
        configPanel.add(customCheckBox, c);

        customField = new JTextField(20);
        c.gridx = 1;
        configPanel.add(customField, c);

        // Add save button at the bottom
        row++;
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 2;
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> saveConfig());
        configPanel.add(saveButton, c);
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
                for (File file : dir.listFiles()) {
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

            TomlWriter tomlWriter = new TomlWriter();
            tomlWriter.write(data, new File(configFilePath));
            callbacks.printOutput("Configuration saved successfully.");
        } catch (IOException e) {
            callbacks.printError("Failed to save configuration: " + e.getMessage());
        }
    }

    @Override
    public String getTabCaption() {
        return "BFFFUF Config";
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

                    java.util.List<String> fuzzMarkers = new ArrayList<>();
                    for (int i = 1; i <= 4; i++) {
                        if (requestString.contains("FUZZ" + i)) {
                            fuzzMarkers.add("FUZZ" + i);
                            callbacks.printOutput("Found marker: FUZZ" + i);
                        }
                    }

                    boolean sniperMarkerFound = false;
                    if (mode.equals("sniper") && requestString.contains("SNIPER")) {
                        requestString = requestString.replace("SNIPER", "§§");
                        sniperMarkerFound = true;
                    }

                    String requestFilePath = saveRequestToFile(requestString, host);
                    callbacks.printOutput("Request saved to: " + requestFilePath);
                    executeFFUF(requestFilePath, fuzzMarkers, sniperMarkerFound, mode);
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

        private void executeFFUF(String requestFilePath, java.util.List<String> fuzzMarkers, boolean sniperMarkerFound, String mode) throws IOException {
            java.util.List<String> command = new ArrayList<>();
            command.add("ffuf");

            boolean wordlistAdded = false;
            if (sniperMarkerFound && sniperWordlistField.getText() != null && !sniperWordlistField.getText().isEmpty()) {
                command.add("-w");
                command.add(sniperWordlistField.getText());
                callbacks.printOutput("Adding sniper wordlist: " + sniperWordlistField.getText());
                wordlistAdded = true;
            } else {
                for (int i = 0; i < fuzzMarkers.size(); i++) {
                    if (wordlistFields[i].getText() != null && !wordlistFields[i].getText().isEmpty()) {
                        command.add("-w");
                        command.add(wordlistFields[i].getText() + ":" + fuzzMarkers.get(i));
                        callbacks.printOutput("Adding wordlist: " + wordlistFields[i].getText() + " for marker: " + fuzzMarkers.get(i));
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
                command.add("-D");
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
                command.add("-recursion");
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
                cmdArray = new String[]{"x-terminal-emulator", "-e", commandString};
            } else {
                throw new IOException("Unsupported OS: " + os);
            }

            ProcessBuilder processBuilder = new ProcessBuilder(cmdArray);
            processBuilder.inheritIO();
            processBuilder.start();
        }
    }
}