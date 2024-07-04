// screens/HomeScreen.js
import React from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';

export default function HomeScreen({ navigation }) {
  return (
    <View style={styles.container}>
      <Text>Welcome to HealthApp</Text>
      <Button title="Request Ambulance" onPress={() => navigation.navigate('AmbulanceService')} />
      <Button title="Doctor Appointments" onPress={() => navigation.navigate('DoctorAppointments')} />
      <Button title="Job Board" onPress={() => navigation.navigate('JobBoard')} />
      <Button title="Healthcare Requests" onPress={() => navigation.navigate('HealthcareRequests')} />
      <Button title="Profile" onPress={() => navigation.navigate('Profile')} />
      <Button title="Notifications" onPress={() => navigation.navigate('Notifications')} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
});
