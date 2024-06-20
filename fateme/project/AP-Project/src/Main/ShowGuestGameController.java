package Main;

import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.io.IOException;
import java.util.Timer;
import java.util.TimerTask;

public class ShowGuestGameController extends GameScene{

    @FXML
    private TextField firstnameTxt;

    @FXML
    private TextField lastnameTxt;

    @FXML
    private TextField animalTxt;

    @FXML
    private TextField carTxt;

    @FXML
    private TextField cityTxt;

    @FXML
    private TextField clothesTxt;

    @FXML
    private TextField countryTxt;

    @FXML
    private TextField flowerTxt;

    @FXML
    private TextField foodTxt;

    @FXML
    private TextField fruitTxt;

    @FXML
    private TextField thingsTxt;

    @FXML
    private Button submitBttn;

    @FXML
    private Button stopBttn;

    @FXML
    private Button startBttn;

    @FXML
    private Label gTimeLbl;

    int gSeconds;

    public ShowGuestGameController(){
    }

    @FXML
    public void startButtonPushed(){
        try {
            client.writer.writeUTF("Get Game Fields");
            int size = Integer.parseInt(client.reader.readUTF());
            for(int i = 0; i < size; i++){
                String field = client.reader.readUTF();
                if(field.equals("Firstname"))
                    firstnameTxt.setDisable(false);
                else if(field.equals("Lastname"))
                    lastnameTxt.setDisable(false);
                else if(field.equals("Animal"))
                    animalTxt.setDisable(false);
                else if(field.equals("Car"))
                    carTxt.setDisable(false);
                else if(field.equals("City"))
                    cityTxt.setDisable(false);
                else if(field.equals("Clothes"))
                    clothesTxt.setDisable(false);
                else if(field.equals("Country"))
                    countryTxt.setDisable(false);
                else if(field.equals("Flower"))
                    flowerTxt.setDisable(false);
                else if(field.equals("Food"))
                    foodTxt.setDisable(false);
                else if(field.equals("Fruit"))
                    fruitTxt.setDisable(false);
                else if(field.equals("Things"))
                    thingsTxt.setDisable(false);
            }
            String str = client.reader.readUTF();
            System.out.println(str);
            if(str.equals("Time")){
                submitBttn.setDisable(true);
                gSeconds = 60;
                gTimer();
            }
        }catch(Exception exception){
            exception.printStackTrace();
        }
    }
    @FXML
    public void submitButtonPushed(){
        try {
            client.writer.writeUTF("Fields' Concept");
            String sSize = client.reader.readUTF();
            int size = Integer.parseInt(sSize);
            for(int i = 0; i < size; i++) {
                String field = client.reader.readUTF();
                if(field.equals("Firstname")) {
                    String str = firstnameTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Lastname")) {
                    String str = lastnameTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Animal")) {
                    String str = animalTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Car")){
                    String str = carTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("City")){
                    String str = cityTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Clothes")){
                    String str = clothesTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Country")) {
                    String str = countryTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Flower")){
                    String str = flowerTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Food")){
                    String str = foodTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Fruit")){
                    String str = fruitTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Things")){
                    String str = thingsTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
            }
        }catch(Exception exception){
            exception.printStackTrace();
        }
    }
    public void stopButtonPushed(){
        EventHandler<ActionEvent> event = e -> {
            try {
                    //client.reader.readUTF();
                    Parent ratingParent = FXMLLoader.load(getClass().getResource("ShowRating.fxml"));
                    Scene ratingScene = new Scene(ratingParent);
                    //this line gets the stage information
                    Stage window = (Stage) ((Node) e.getSource()).getScene().getWindow();
                    window.setScene(ratingScene);
                    window.show();
            }catch (Exception exception){}
        };
        stopBttn.setOnAction(event);
    }
    public void gTimer(){
        gTimeLbl.setDisable(false);
        Timeline timeline = new Timeline();
        timeline.setCycleCount(Timeline.INDEFINITE);
        KeyFrame keyFrame = new KeyFrame(Duration.seconds(1), new EventHandler<ActionEvent>(){
            @Override
            public void handle(ActionEvent event){
                gSeconds--;
                gTimeLbl.setText("" + gSeconds);
                if(gSeconds <= 0) {
                    submitBttn.setDisable(false);
                    timeline.stop();
                }
            }
        });
        timeline.getKeyFrames().add(keyFrame);
        timeline.playFromStart();
    }
}