package main;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.rmi.Naming;

import javax.swing.*;
import javax.swing.border.*;

public class GUI extends JFrame {

    private static final long serialVersionUID = 1L;
    private static final int WIDTH = 1200;
    private static final int HEIGHT = 800;

    private static MedicalService server;
    private static Frontend front;
    private GridBagConstraints c = new GridBagConstraints();

    private JPanel welcomeWin;
    private JPanel welcomeButs;

    private JPanel loginWin;
    private JPanel loginForm;
    private JPanel loginButs;
    private JPanel authWin;

    private JPanel registerWin;
    private JPanel registerForm;
    private JPanel registerButs;

    private JTextField userIn;
    private JPasswordField passIn;
    private JPasswordField confirmPassIn;
    private JTextField authIn;

    private JLabel title;
    private JLabel userLab;
    private JLabel passLab;
    private JLabel confirmPassLab;
    private JLabel authLab;

    private JButton loginLand;
    private JButton registerLand;
    private JButton registerBut;
    private JButton loginBut;
    private JButton backBut;

    private GUI() {
        front = new Frontend();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(WIDTH, HEIGHT);
        setTitle("Lancaster University Medical Portal");
        setResizable(false);
        switchPanel(landing());
        setVisible(true);
    }

    private JPanel landing() {
        welcomeWin = new JPanel();
        title = new JLabel("Lancaster Medical Center", JLabel.CENTER);
        title.setFont(new Font("Helvetica", Font.BOLD, 40));
        title.setBorder(new EmptyBorder(0, 60, 0, 20));
        
        welcomeButs = new JPanel();
        loginLand = new JButton("Login");
        loginLand.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    switchPanel(login());
                } catch (Exception exception) {
                    exception.printStackTrace();
                }
            }
        });
        welcomeButs.add(loginLand);

        registerLand = new JButton("Register");
        registerLand.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    switchPanel(register());
                } catch (Exception exception) {
                    exception.printStackTrace();
                }
            }
        });
        welcomeButs.add(registerLand);

        title.setHorizontalAlignment(JLabel.CENTER);
        welcomeWin.setLayout(new GridBagLayout());
        c.fill = GridBagConstraints.VERTICAL;
        c.insets = new Insets(10, 0, 0, 0);
        c.gridy = 0;
        welcomeWin.add(title, c);
        c.gridy = 1;
        welcomeWin.add(welcomeButs, c);

        return welcomeWin;
    }

    private JPanel login() {
        loginWin = new JPanel();
        loginForm = new JPanel(new GridBagLayout());
        c.fill = GridBagConstraints.HORIZONTAL;

        userLab = new JLabel("Username: ");
        userIn = new JTextField(15);
        passLab = new JLabel("Password: ");
        passIn = new JPasswordField(40);
        authLab = new JLabel("Security Code: ");
        authIn = new JTextField(6);

        c.gridy = 0;
        c.gridx = 0;
        c.gridwidth = 1;
        loginForm.add(userLab, c);
        c.gridy = 1;
        loginForm.add(passLab, c);
        c.gridy = 2;
        loginForm.add(authLab, c);
 
        c.gridx = 1;
        c.gridy = 0;
        c.gridwidth = 2;
        loginForm.add(userIn, c);
        c.gridy = 1;
        loginForm.add(passIn, c);
        c.gridy = 2;
        loginForm.add(authIn, c);

        loginButs = new JPanel();
        loginBut = new JButton("Login");
        loginBut.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    if(front.login(userIn.getText(), new String(passIn.getPassword()), authIn.getText())) {
                        System.out.println("IM IN");
                    } else {
                        System.out.println("nope");
                    }
                } catch (Exception exception) {
                    exception.printStackTrace();
                }
            }
        });
        loginButs.add(loginBut);

        backBut = new JButton("Back");
        backBut.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    switchPanel(landing());
                } catch (Exception exception) {
                    exception.printStackTrace();
                }
            }
        });
        loginButs.add(backBut);

        loginWin.setLayout(new GridBagLayout());
        c.fill = GridBagConstraints.VERTICAL;
        loginWin.add(loginForm, c);
        c.gridy = GridBagConstraints.RELATIVE;
        c.insets = new Insets(10, 0, 0, 0);
        loginWin.add(loginButs, c);

        return loginWin;
    }

    private JPanel register() {
        registerWin = new JPanel();

        registerForm = new JPanel(new GridBagLayout());
        c.fill = GridBagConstraints.HORIZONTAL;

        userLab = new JLabel("Username: ");
        userIn = new JTextField(15);
        passLab = new JLabel("Password: ");
        passIn = new JPasswordField(40);
        confirmPassLab = new JLabel("Confirm Password: ");
        confirmPassIn = new JPasswordField(40);

        c.gridy = 0;
        c.gridx = 0;
        c.gridwidth = 1;
        registerForm.add(userLab, c);
        c.gridy = 1;
        registerForm.add(passLab, c);
        c.gridy = 2;
        registerForm.add(confirmPassLab, c);
 
        c.gridx = 1;
        c.gridy = 0;
        c.gridwidth = 2;
        registerForm.add(userIn, c);
        c.gridy = 1;
        registerForm.add(passIn, c);
        c.gridy = 2;
        registerForm.add(confirmPassIn, c);

        registerButs = new JPanel();
        registerBut = new JButton("Register");
        registerBut.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    // input and setUpAuthentication();
                    System.out.println(userIn.getText());
                    System.out.println(new String(passIn.getPassword()));
                } catch (Exception exception) {
                    exception.printStackTrace();
                }
            }
        });
        registerButs.add(registerBut);

        backBut = new JButton("Back");
        backBut.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    switchPanel(landing());
                } catch (Exception exception) {
                    exception.printStackTrace();
                }
            }
        });
        registerButs.add(backBut);

        registerWin.setLayout(new GridBagLayout());
        c.fill = GridBagConstraints.VERTICAL;
        registerWin.add(registerForm, c);
        c.gridy = GridBagConstraints.RELATIVE;
        c.insets = new Insets(10, 0, 0, 0);
        registerWin.add(registerButs, c);

        return registerWin;
    }

    public void switchPanel(JPanel panel) {
        getContentPane().removeAll();
        add(panel);
        revalidate();
        repaint();
    }
    public static void main(String[] args) {
        new GUI();
    }
}
