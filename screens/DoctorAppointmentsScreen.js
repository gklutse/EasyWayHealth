
// screens/DoctorAppointmentsScreen.js
import React from 'react';
import { View, Text, Button, FlatList, StyleSheet } from 'react-native';

const doctors = [
  { id: '1', name: 'Dr. John Doe', specialty: 'Cardiologist' },
  { id: '2', name: 'Dr. Jane Smith', specialty: 'Dermatologist' },
  // Add more doctors here
];

export default function DoctorAppointmentsScreen({ navigation }) {
  const renderItem = ({ item }) => (
    <View style={styles.item}>
      <Text>{item.name}</Text>
      <Text>{item.specialty}</Text>
      <Button title="View Details" onPress={() => navigation.navigate('DoctorDetails', { doctor: item })} />
    </View>
  );

  return (
    <View style={styles.container}>
      <Text>Book a Doctor Appointment</Text>
      <FlatList
        data={doctors}
        renderItem={renderItem}
        keyExtractor={(item) => item.id}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 16,
  },
  item: {
    backgroundColor: '#f9c2ff',
    padding: 20,
    marginVertical: 8,
    marginHorizontal: 16,
  },
});
