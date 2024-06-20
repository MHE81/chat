package main;

import java.util.ArrayList;

public class GameControl{
    public String mainLetter;
    FirstName firstname;
    Lastname lastname;
    Animal animal;
    Food food;
    City city;
    Country country;
    Fruit fruit;
    Flower flower;
    Car car;
    Things things;
    Clothes clothes;

    public GameControl(){
    }

    public void setGameControl(ArrayList<String> gameFields, String letter){
        mainLetter = letter;
        System.out.println(mainLetter);
        for(int i = 0; i < gameFields.size(); i++){

            if(gameFields.get(i).equals("Firstname")) {
                firstname = new FirstName(mainLetter);
                firstname.setInGame();
            }
            else if(gameFields.get(i).equals("Lastname")){
                lastname = new Lastname(mainLetter);
                lastname.setInGame();
            }
            else if(gameFields.get(i).equals("Animal")){
                animal = new Animal(mainLetter);
                animal.setInGame();
            }
            else if(gameFields.get(i).equals("Food")){
                food = new Food(mainLetter);
                food.setInGame();
            }
            else if(gameFields.get(i).equals("City")){
                city = new City(mainLetter);
                city.setInGame();
            }
            else if(gameFields.get(i).equals("Country")){
                country = new Country(mainLetter);
                country.setInGame();
            }
            else if(gameFields.get(i).equals("Fruit")){
               fruit = new Fruit(mainLetter);
               fruit.setInGame();
            }
            else if(gameFields.get(i).equals("Flower")){
                flower = new Flower(mainLetter);
                flower.setInGame();
            }
            else if(gameFields.get(i).equals("Car")){
               car = new Car(mainLetter);
               car.setInGame();
            }
            else if(gameFields.get(i).equals("Things")){
                things = new Things(mainLetter);
                things.setInGame();
            }
            else if(gameFields.get(i).equals("Clothes")){
                clothes = new Clothes(mainLetter);
                clothes.setInGame();
            }
        }
    }

    public int setConcepts(String[][] concepts){
        int totalRate = 0;
        try {
            for (int i = 0; i < concepts.length; i++) {
                if(concepts[i][0].equals("Firstname")) {
                    firstname.setConcept(concepts[i][1]);
                    if(firstname.isNameAccepted())
                        totalRate += 10;
                }

                else if(concepts[i][0].equals("Lastname")) {
                    lastname.setConcept(concepts[i][1]);
                    if(lastname.isNameAccepted())
                        totalRate += 10;
                }

                else if(concepts[i][0].equals("Animal")) {
                    animal.setConcept(concepts[i][1]);
                    if(animal.isNameAccepted())
                        totalRate += 10;
                }

                else if(concepts[i][0].equals("Car")) {
                    car.setConcept(concepts[i][1]);
                    if(car.isNameAccepted())
                        totalRate += 10;
                }

                else if(concepts[i][0].equals("City")) {
                    city.setConcept(concepts[i][1]);
                    if(city.isNameAccepted())
                        totalRate += 10;
                }

                else if(concepts[i][0].equals("Clothes")) {
                    clothes.setConcept(concepts[i][1]);
                    if(clothes.isNameAccepted())
                        totalRate += 10;
                }

                else if(concepts[i][0].equals("Country")) {
                    country.setConcept(concepts[i][1]);
                    if(country.isNameAccepted())
                        totalRate += 10;
                }

                else if(concepts[i][0].equals("Flower")){
                    flower.setConcept(concepts[i][1]);
                    if (flower.isNameAccepted())
                        totalRate += 10;
                }

                else if(concepts[i][0].equals("Food")) {
                    food.setConcept(concepts[i][1]);
                    if (food.isNameAccepted())
                        totalRate += 10;
                }

                else if(concepts[i][0].equals("Fruit")) {
                    fruit.setConcept(concepts[i][1]);
                    if (fruit.isNameAccepted())
                        totalRate += 10;
                }

                else if(concepts[i][0].equals("Things")) {
                    things.setConcept(concepts[i][1]);
                    if (things.isNameAccepted())
                        totalRate += 10;
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        finally {
            return totalRate;
        }
    }
}
