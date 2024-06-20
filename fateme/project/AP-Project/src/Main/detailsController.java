package Main;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.Stage;

import java.io.IOException;
import java.util.ArrayList;

public class detailsController extends GameScene{

    static Info information = new Info();
    static ObservableList<String> letterList = FXCollections.observableList(information.letters);
    @FXML
    private ComboBox letterCombo;

    @FXML
    private CheckBox firstnameCheck;

    @FXML
    private CheckBox lastnameCheck;

    @FXML
    private CheckBox countryCheck;

    @FXML
    private CheckBox foodCheck;

    @FXML
    private CheckBox clothesCheck;

    @FXML
    private CheckBox fruitCheck;

    @FXML
    private CheckBox carCheck;

    @FXML
    private CheckBox animalCheck;

    @FXML
    private CheckBox thingCheck;

    @FXML
    private CheckBox cityCheck;

    @FXML
    private CheckBox flowerCheck;

    int checkBoxCount = 0;

    @FXML
    private void initialize(){
        letterCombo.setItems(letterList);
    }

    @FXML
    public void backButtonPushed(ActionEvent event) throws IOException {
        Parent newGameParent = FXMLLoader.load(getClass().getResource("newGame.fxml"));
        Scene newGameScene = new Scene(newGameParent);

        //this line gets the stage information
        Stage window = (Stage) ((Node)event.getSource()).getScene().getWindow();
        window.setScene(newGameScene);
        window.show();
    }

    @FXML
    public void continueButtonPushed(ActionEvent event){
        try {
            ArrayList<String> selectedFields = new ArrayList<>();
            if(firstnameCheck.isSelected()){
                selectedFields.add("Firstname");
                checkBoxCount++;
            }
            if(lastnameCheck.isSelected()){
                selectedFields.add("Lastname");
                checkBoxCount++;
            }
            if(fruitCheck.isSelected()){
                selectedFields.add("Fruit");
                checkBoxCount++;
            }
            if(animalCheck.isSelected()){
                selectedFields.add("Animal");
                checkBoxCount++;
            }
            if(foodCheck.isSelected()){
                selectedFields.add("Food");
                checkBoxCount++;
            }
            if(carCheck.isSelected()){
                selectedFields.add("Car");
                checkBoxCount++;
            }
            if(thingCheck.isSelected()){
                selectedFields.add("Things");
                checkBoxCount++;
            }
            if(countryCheck.isSelected()){
                selectedFields.add("Country");
                checkBoxCount++;
            }
            if(cityCheck.isSelected()){
                selectedFields.add("City");
                checkBoxCount++;
            }
            if(clothesCheck.isSelected()){
                selectedFields.add("Clothes");
                checkBoxCount++;
            }
            if(flowerCheck.isSelected()){
                selectedFields.add("Flower");
                checkBoxCount++;
            }
            if(checkBoxCount <= 4){
                Alert alert = new Alert(Alert.AlertType.WARNING);
                alert.setTitle("هشدار");
                alert.setHeaderText("عدم انتخاب فیلد کافی");
                alert.setContentText("انتخاب حداقل پنج فیلد از یازده فیلد موضاعات بازی الزامی است!");
                alert.showAndWait();
            }
            else {
                String mainLetter = (String) letterCombo.getValue();
                letterList.remove(mainLetter);
                client.writer.writeUTF("Game Details");
                client.writer.writeUTF(mainLetter);
                String size = String.valueOf(selectedFields.size());
                client.writer.writeUTF(size);
                System.out.println(size);
                for (int i = 0; i < selectedFields.size(); i++) {
                    String field = selectedFields.get(i);
                    System.out.println(field);
                    client.writer.writeUTF(field);
                }
                client.writer.writeUTF("End");
                System.out.println("Main Letter: " + mainLetter);
                String str = client.reader.readUTF();
                if (str.equals("Start")) {
                    Parent hGameParent = FXMLLoader.load(getClass().getResource("ShowGame.fxml"));
                    Scene hGameScene = new Scene(hGameParent);

                    //this line gets the stage information
                    Stage window = (Stage) ((Node) event.getSource()).getScene().getWindow();
                    window.setScene(hGameScene);
                    window.show();
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

//    public ArrayList<String> getSelectedCheckBoxes(){
//        ArrayList<String> selectedFields = new ArrayList<>();
//        if(firstnameCheck.isSelected()){
//            selectedFields.add("Firstname");
//            checkBoxCount++;
//        }
//        if(lastnameCheck.isSelected()){
//            selectedFields.add("Lastname");
//            checkBoxCount++;
//        }
//        if(fruitCheck.isSelected()){
//            selectedFields.add("Fruit");
//            checkBoxCount++;
//        }
//        if(animalCheck.isSelected()){
//            selectedFields.add("Animal");
//            checkBoxCount++;
//        }
//        if(foodCheck.isSelected()){
//            selectedFields.add("Food");
//            checkBoxCount++;
//        }
//        if(carCheck.isSelected()){
//            selectedFields.add("Car");
//            checkBoxCount++;
//        }
//        if(thingCheck.isSelected()){
//            selectedFields.add("Things");
//            checkBoxCount++;
//        }
//        if(countryCheck.isSelected()){
//            selectedFields.add("Country");
//            checkBoxCount++;
//        }
//        if(cityCheck.isSelected()){
//            selectedFields.add("City");
//            checkBoxCount++;
//        }
//        if(clothesCheck.isSelected()){
//            selectedFields.add("Clothes");
//            checkBoxCount++;
//        }
//        if(flowerCheck.isSelected()){
//            selectedFields.add("Flower");
//            checkBoxCount++;
//        }
//        if(checkBoxCount <= 4){
//            Alert alert = new Alert(Alert.AlertType.WARNING);
//            alert.setTitle("هشدار");
//            alert.setHeaderText("عدم انتخاب فیلد کافی");
//            alert.setContentText("انتخاب حداقل پنج فیلد از یازده فیلد موضاعات بازی الزامی است!");
//            alert.showAndWait();
//        }
//        return selectedFields;
//    }
}
